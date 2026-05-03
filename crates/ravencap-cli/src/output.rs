use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use ravencap_core::{InspectInfo, VerifyReport};
use tempfile::NamedTempFile;

pub(crate) fn write_text_output(
    path: Option<&PathBuf>,
    overwrite: bool,
    contents: &str,
) -> Result<()> {
    with_output(path, overwrite, |output| {
        output
            .write_all(contents.as_bytes())
            .context("failed to write output")
    })
}

pub(crate) fn open_input(path: Option<&PathBuf>) -> Result<Box<dyn Read>> {
    match path {
        Some(path) => Ok(Box::new(BufReader::new(
            File::open(path).with_context(|| format!("failed to open input {}", path.display()))?,
        ))),
        None => Ok(Box::new(BufReader::new(std::io::stdin().lock()))),
    }
}

pub(crate) fn open_command_input(path: &str) -> Result<Box<dyn Read>> {
    if path == "-" {
        Ok(Box::new(BufReader::new(std::io::stdin().lock())))
    } else {
        Ok(Box::new(BufReader::new(File::open(path).with_context(
            || format!("failed to open input {path}"),
        )?)))
    }
}

pub(crate) fn write_public_info(
    mut output: impl Write,
    info: &ravencap_core::PublicInfo,
) -> Result<()> {
    writeln!(output, "age_compatible: {}", info.age_compatible)
        .context("failed to write info output")?;
    for note in &info.notes {
        writeln!(output, "note: {note}").context("failed to write info output")?;
    }
    Ok(())
}

pub(crate) fn write_inspect_report(
    mut output: impl Write,
    info: &InspectInfo,
    json: bool,
) -> Result<()> {
    if json {
        serde_json::to_writer_pretty(&mut output, info).context("failed to write inspect JSON")?;
        writeln!(output).context("failed to write inspect JSON")?;
        return Ok(());
    }

    writeln!(output, "{}", ravencap_core::INSPECT_WARNING)
        .context("failed to write inspect output")?;
    writeln!(output, "Payload type: {}", info.payload_type)
        .context("failed to write inspect output")?;
    writeln!(output, "Compression: {}", info.compression)
        .context("failed to write inspect output")?;
    writeln!(output, "Files: {}", info.files).context("failed to write inspect output")?;
    writeln!(output, "Directories: {}", info.directories)
        .context("failed to write inspect output")?;
    writeln!(output, "Symlinks: {}", info.symlinks).context("failed to write inspect output")?;
    writeln!(output, "Uncompressed size: {}", info.uncompressed_size)
        .context("failed to write inspect output")?;
    writeln!(output, "Manifest version: {}", info.manifest_version)
        .context("failed to write inspect output")?;
    writeln!(output, "Content stream verified: false").context("failed to write inspect output")?;
    Ok(())
}

pub(crate) fn write_verify_report(
    mut output: impl Write,
    report: &VerifyReport,
    json: bool,
) -> Result<()> {
    if json {
        serde_json::to_writer_pretty(&mut output, report).context("failed to write verify JSON")?;
        writeln!(output).context("failed to write verify JSON")?;
        return Ok(());
    }

    match report.mode.as_str() {
        "quick" if report.success => {
            writeln!(
                output,
                "Quick verify completed: encrypted stream authenticated."
            )
            .context("failed to write verify output")?;
            writeln!(
                output,
                "Archive manifest and file checksums were NOT verified."
            )
            .context("failed to write verify output")?;
            writeln!(output, "Run `Ravencap verify` for full verification.")
                .context("failed to write verify output")?;
        }
        _ => {
            writeln!(output, "Verify mode: {}", report.mode)
                .context("failed to write verify output")?;
            writeln!(output, "Success: {}", report.success)
                .context("failed to write verify output")?;
            for note in &report.notes {
                writeln!(output, "Note: {note}").context("failed to write verify output")?;
            }
        }
    }

    Ok(())
}

pub(crate) fn with_output(
    path: Option<&PathBuf>,
    overwrite: bool,
    operation: impl FnOnce(&mut dyn Write) -> Result<()>,
) -> Result<()> {
    match path {
        Some(path) => {
            let mut output = ManagedFileOutput::create(path, overwrite)?;
            operation(&mut output)?;
            output.commit()
        }
        None => {
            let stdout = std::io::stdout();
            let mut output = BufWriter::new(stdout.lock());
            operation(&mut output)?;
            output.flush().context("failed to flush stdout")
        }
    }
}

struct ManagedFileOutput {
    final_path: PathBuf,
    overwrite: bool,
    temp: Option<NamedTempFile>,
    writer: Option<BufWriter<File>>,
}

impl ManagedFileOutput {
    fn create(final_path: &Path, overwrite: bool) -> Result<Self> {
        if final_path.exists() && !overwrite {
            bail!(
                "output {} already exists; pass --overwrite to replace it",
                final_path.display()
            );
        }

        let directory = final_path.parent().unwrap_or_else(|| Path::new("."));
        let temp = NamedTempFile::new_in(directory).with_context(|| {
            format!(
                "failed to create temporary output beside {}",
                final_path.display()
            )
        })?;
        let writer = BufWriter::new(temp.reopen().with_context(|| {
            format!(
                "failed to reopen temporary output for {}",
                final_path.display()
            )
        })?);

        Ok(Self {
            final_path: final_path.to_path_buf(),
            overwrite,
            temp: Some(temp),
            writer: Some(writer),
        })
    }

    fn commit(mut self) -> Result<()> {
        let mut writer = self.writer.take().expect("managed output writer missing");
        writer.flush().with_context(|| {
            format!(
                "failed to flush temporary output for {}",
                self.final_path.display()
            )
        })?;
        writer.get_ref().sync_all().with_context(|| {
            format!(
                "failed to sync temporary output for {}",
                self.final_path.display()
            )
        })?;
        drop(writer);

        let temp = self.temp.take().expect("managed output tempfile missing");
        if self.overwrite {
            temp.persist(&self.final_path).map_err(|error| {
                anyhow::anyhow!(
                    "failed to commit temporary output to {}: {}",
                    self.final_path.display(),
                    error.error
                )
            })?;
        } else {
            temp.persist_noclobber(&self.final_path).map_err(|error| {
                anyhow::anyhow!(
                    "failed to commit temporary output to {}: {}",
                    self.final_path.display(),
                    error.error
                )
            })?;
        }

        Ok(())
    }
}

impl Write for ManagedFileOutput {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.writer
            .as_mut()
            .expect("managed output writer missing")
            .write(buffer)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.writer
            .as_mut()
            .expect("managed output writer missing")
            .flush()
    }
}
