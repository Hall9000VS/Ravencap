use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use ravencap_core::{
    EncryptOptions, Identity, InspectInfo, PackOptions, Recipient, UnpackOptions, VerifyMode,
    VerifyReport,
};
use tempfile::NamedTempFile;

#[derive(Parser)]
#[command(name = "ravencap", version, about = "Streaming encrypted archive tool")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Pack(PackCommand),
    Unpack(UnpackCommand),
    Encrypt(CryptoCommand),
    Decrypt(CryptoCommand),
    Info(PathCommand),
    Inspect(InspectCommand),
    Verify(VerifyCommand),
    Keygen(OutputCommand),
    Pubkey(PathCommand),
}

#[derive(Args)]
struct PathCommand {
    input: String,

    #[arg(short, long)]
    output: Option<PathBuf>,

    #[arg(long)]
    overwrite: bool,
}

#[derive(Args)]
struct PackCommand {
    input: PathBuf,

    #[arg(short, long)]
    output: Option<PathBuf>,

    #[arg(long)]
    overwrite: bool,

    #[arg(long = "insecure-passphrase-cli")]
    insecure_passphrase_cli: Option<String>,

    #[arg(long)]
    passphrase_file: Option<PathBuf>,

    #[arg(short = 'r', long = "recipient")]
    recipients: Vec<String>,
}

#[derive(Args)]
struct UnpackCommand {
    input: String,

    #[arg(short, long)]
    output: PathBuf,

    #[arg(long = "insecure-passphrase-cli")]
    insecure_passphrase_cli: Option<String>,

    #[arg(long)]
    passphrase_file: Option<PathBuf>,

    #[arg(long = "identity")]
    identities: Vec<PathBuf>,
}

#[derive(Args)]
struct CryptoCommand {
    #[arg(short, long)]
    input: Option<PathBuf>,

    #[arg(short, long)]
    output: Option<PathBuf>,

    #[arg(long)]
    overwrite: bool,

    #[arg(long = "insecure-passphrase-cli")]
    insecure_passphrase_cli: Option<String>,

    #[arg(long)]
    passphrase_file: Option<PathBuf>,

    #[arg(short = 'r', long = "recipient")]
    recipients: Vec<String>,

    #[arg(long = "identity")]
    identities: Vec<PathBuf>,
}

#[derive(Args)]
struct VerifyCommand {
    input: String,

    #[arg(long)]
    quick: bool,

    #[arg(long)]
    json: bool,

    #[arg(long = "insecure-passphrase-cli")]
    insecure_passphrase_cli: Option<String>,

    #[arg(long)]
    passphrase_file: Option<PathBuf>,

    #[arg(long = "identity")]
    identities: Vec<PathBuf>,
}

#[derive(Args)]
struct InspectCommand {
    input: String,

    #[arg(short, long)]
    output: Option<PathBuf>,

    #[arg(long)]
    overwrite: bool,

    #[arg(long)]
    json: bool,

    #[arg(long = "insecure-passphrase-cli")]
    insecure_passphrase_cli: Option<String>,

    #[arg(long)]
    passphrase_file: Option<PathBuf>,

    #[arg(long = "identity")]
    identities: Vec<PathBuf>,
}

#[derive(Args)]
struct OutputCommand {
    #[arg(short, long)]
    output: Option<PathBuf>,

    #[arg(long)]
    overwrite: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Pack(args) => {
            let recipients = resolve_recipients(
                args.insecure_passphrase_cli,
                args.passphrase_file,
                args.recipients,
            )?;
            let options = recipients
                .into_iter()
                .fold(PackOptions::new(), |options, recipient| {
                    options.recipient(recipient)
                });
            with_output(args.output.as_ref(), args.overwrite, |output| {
                Ok(ravencap_core::pack_path(args.input, output, options)?)
            })?;
        }
        Command::Unpack(args) => {
            let identities = resolve_identities(
                args.insecure_passphrase_cli,
                args.passphrase_file,
                args.identities,
            )?;
            let input = open_command_input(&args.input)?;
            let options = identities
                .into_iter()
                .fold(UnpackOptions::new(), |options, identity| {
                    options.identity(identity)
                });
            ravencap_core::unpack_archive(input, args.output, options)?;
        }
        Command::Encrypt(args) => {
            let recipients = resolve_recipients(
                args.insecure_passphrase_cli,
                args.passphrase_file,
                args.recipients,
            )?;
            let input = open_input(args.input.as_ref())?;
            let options = recipients
                .into_iter()
                .fold(EncryptOptions::new(), |options, recipient| {
                    options.recipient(recipient)
                });
            with_output(args.output.as_ref(), args.overwrite, |output| {
                Ok(ravencap_core::encrypt_stream(input, output, options)?)
            })?;
        }
        Command::Decrypt(args) => {
            let identities = resolve_identities(
                args.insecure_passphrase_cli,
                args.passphrase_file,
                args.identities,
            )?;
            let input = open_input(args.input.as_ref())?;
            with_output(args.output.as_ref(), args.overwrite, |output| {
                Ok(ravencap_core::decrypt_stream(input, output, identities)?)
            })?;
        }
        Command::Info(args) => {
            let input = open_command_input(&args.input)?;
            let info = ravencap_core::read_public_info(input)?;
            with_output(args.output.as_ref(), args.overwrite, |output| {
                write_public_info(output, &info)
            })?;
        }
        Command::Inspect(args) => {
            let identities = resolve_identities(
                args.insecure_passphrase_cli,
                args.passphrase_file,
                args.identities,
            )?;
            let input = open_command_input(&args.input)?;
            let info = ravencap_core::inspect_manifest(input, identities)?;
            with_output(args.output.as_ref(), args.overwrite, |output| {
                write_inspect_report(output, &info, args.json)
            })?;
        }
        Command::Verify(args) => {
            let identities = resolve_identities(
                args.insecure_passphrase_cli,
                args.passphrase_file,
                args.identities,
            )?;
            let input = open_command_input(&args.input)?;
            let mode = if args.quick {
                VerifyMode::Quick
            } else {
                VerifyMode::Full
            };
            let report = ravencap_core::verify_archive(input, identities, mode)?;
            write_verify_report(std::io::stdout().lock(), &report, args.json)?;
        }
        Command::Keygen(args) => {
            let identity = ravencap_core::generate_private_key();
            write_text_output(
                args.output.as_ref(),
                args.overwrite,
                &format!("{identity}\n"),
            )?;
        }
        Command::Pubkey(args) => {
            let private_key = std::fs::read_to_string(&args.input)
                .with_context(|| format!("failed to read identity file {}", args.input))?;
            let public_key = ravencap_core::public_key_from_private_key(&private_key)?;
            write_text_output(
                args.output.as_ref(),
                args.overwrite,
                &format!("{public_key}\n"),
            )?;
        }
    }

    Ok(())
}

fn resolve_recipients(
    insecure_passphrase_cli: Option<String>,
    passphrase_file: Option<PathBuf>,
    recipients: Vec<String>,
) -> Result<Vec<Recipient>> {
    let passphrase = resolve_optional_passphrase(insecure_passphrase_cli, passphrase_file)?;

    let mut resolved = Vec::new();
    if let Some(passphrase) = passphrase {
        resolved.push(Recipient::passphrase(passphrase));
    } else if recipients.is_empty() {
        resolved.push(Recipient::passphrase(
            rpassword::prompt_password("Passphrase: ").context("failed to read passphrase")?,
        ));
    }
    resolved.extend(recipients.into_iter().map(Recipient::public_key));
    Ok(resolved)
}

fn resolve_identities(
    insecure_passphrase_cli: Option<String>,
    passphrase_file: Option<PathBuf>,
    identities: Vec<PathBuf>,
) -> Result<Vec<Identity>> {
    let passphrase = resolve_optional_passphrase(insecure_passphrase_cli, passphrase_file)?;

    let mut resolved = Vec::new();
    if let Some(passphrase) = passphrase {
        resolved.push(Identity::passphrase(passphrase));
    } else if identities.is_empty() {
        resolved.push(Identity::passphrase(
            rpassword::prompt_password("Passphrase: ").context("failed to read passphrase")?,
        ));
    }

    for path in identities {
        let private_key = std::fs::read_to_string(&path)
            .with_context(|| format!("failed to read identity file {}", path.display()))?;
        resolved.push(Identity::private_key(private_key));
    }

    Ok(resolved)
}

fn resolve_optional_passphrase(
    insecure_passphrase_cli: Option<String>,
    passphrase_file: Option<PathBuf>,
) -> Result<Option<String>> {
    if insecure_passphrase_cli.is_some() && passphrase_file.is_some() {
        bail!("use only one of --insecure-passphrase-cli or --passphrase-file");
    }

    if let Some(passphrase) = insecure_passphrase_cli {
        eprintln!(
            "warning: --insecure-passphrase-cli exposes secrets through process listings and shell history; prefer --passphrase-file or the interactive prompt"
        );
        return Ok(Some(passphrase));
    }

    if let Some(path) = passphrase_file {
        let value = std::fs::read_to_string(&path)
            .with_context(|| format!("failed to read passphrase file {}", path.display()))?;
        return Ok(Some(value.trim_end_matches(['\r', '\n']).to_string()));
    }

    Ok(None)
}

fn write_text_output(path: Option<&PathBuf>, overwrite: bool, contents: &str) -> Result<()> {
    with_output(path, overwrite, |output| {
        output
            .write_all(contents.as_bytes())
            .context("failed to write output")
    })
}

fn open_input(path: Option<&PathBuf>) -> Result<Box<dyn Read>> {
    match path {
        Some(path) => Ok(Box::new(BufReader::new(
            File::open(path).with_context(|| format!("failed to open input {}", path.display()))?,
        ))),
        None => Ok(Box::new(BufReader::new(std::io::stdin().lock()))),
    }
}

fn open_command_input(path: &str) -> Result<Box<dyn Read>> {
    if path == "-" {
        Ok(Box::new(BufReader::new(std::io::stdin().lock())))
    } else {
        Ok(Box::new(BufReader::new(File::open(path).with_context(
            || format!("failed to open input {path}"),
        )?)))
    }
}

fn write_public_info(mut output: impl Write, info: &ravencap_core::PublicInfo) -> Result<()> {
    writeln!(output, "age_compatible: {}", info.age_compatible)
        .context("failed to write info output")?;
    for note in &info.notes {
        writeln!(output, "note: {note}").context("failed to write info output")?;
    }
    Ok(())
}

fn write_inspect_report(mut output: impl Write, info: &InspectInfo, json: bool) -> Result<()> {
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

fn write_verify_report(mut output: impl Write, report: &VerifyReport, json: bool) -> Result<()> {
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

fn with_output(
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
