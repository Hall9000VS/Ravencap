use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use ravencap_core::{EncryptOptions, Identity, PackOptions, Recipient};

#[derive(Parser, Debug)]
#[command(name = "ravencap", version, about = "Streaming encrypted archive tool")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    Pack(PackCommand),
    Unpack(PathCommand),
    Encrypt(CryptoCommand),
    Decrypt(CryptoCommand),
    Info(PathCommand),
    Inspect(PathCommand),
    Verify(VerifyCommand),
    Keygen(OutputCommand),
    Pubkey(PathCommand),
}

#[derive(Args, Debug)]
struct PathCommand {
    input: String,

    #[arg(short, long)]
    output: Option<String>,
}

#[derive(Args, Debug)]
struct PackCommand {
    input: PathBuf,

    #[arg(short, long)]
    output: Option<PathBuf>,

    #[arg(long)]
    passphrase: Option<String>,

    #[arg(long)]
    passphrase_file: Option<PathBuf>,

    #[arg(short = 'r', long = "recipient")]
    recipients: Vec<String>,
}

#[derive(Args, Debug)]
struct CryptoCommand {
    #[arg(short, long)]
    input: Option<PathBuf>,

    #[arg(short, long)]
    output: Option<PathBuf>,

    #[arg(long)]
    passphrase: Option<String>,

    #[arg(long)]
    passphrase_file: Option<PathBuf>,

    #[arg(short = 'r', long = "recipient")]
    recipients: Vec<String>,

    #[arg(long = "identity")]
    identities: Vec<PathBuf>,
}

#[derive(Args, Debug)]
struct VerifyCommand {
    input: String,

    #[arg(long)]
    quick: bool,
}

#[derive(Args, Debug)]
struct OutputCommand {
    #[arg(short, long)]
    output: Option<String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Pack(args) => {
            let recipients =
                resolve_recipients(args.passphrase, args.passphrase_file, args.recipients)?;
            let output = open_output(args.output.as_ref())?;
            let options = recipients
                .into_iter()
                .fold(PackOptions::new(), |options, recipient| {
                    options.recipient(recipient)
                });
            ravencap_core::pack_path(args.input, output, options)?;
        }
        Command::Unpack(args) => {
            println!("unpack scaffold ready for input {}", args.input);
        }
        Command::Encrypt(args) => {
            let recipients =
                resolve_recipients(args.passphrase, args.passphrase_file, args.recipients)?;
            let input = open_input(args.input.as_ref())?;
            let output = open_output(args.output.as_ref())?;
            let options = recipients
                .into_iter()
                .fold(EncryptOptions::new(), |options, recipient| {
                    options.recipient(recipient)
                });
            ravencap_core::encrypt_stream(input, output, options)?;
        }
        Command::Decrypt(args) => {
            let identities =
                resolve_identities(args.passphrase, args.passphrase_file, args.identities)?;
            let input = open_input(args.input.as_ref())?;
            let output = open_output(args.output.as_ref())?;
            ravencap_core::decrypt_stream(input, output, identities)?;
        }
        Command::Info(args) => {
            println!("info scaffold ready for input {}", args.input);
        }
        Command::Inspect(args) => {
            println!("inspect scaffold ready for input {}", args.input);
        }
        Command::Verify(args) => {
            let mode = if args.quick { "quick" } else { "full" };
            println!("verify scaffold ready for input {} ({mode})", args.input);
        }
        Command::Keygen(args) => {
            let identity = ravencap_core::generate_private_key();
            write_text_output(args.output.as_deref(), &format!("{identity}\n"))?;
        }
        Command::Pubkey(args) => {
            let private_key = std::fs::read_to_string(&args.input)
                .with_context(|| format!("failed to read identity file {}", args.input))?;
            let public_key = ravencap_core::public_key_from_private_key(&private_key)?;
            write_text_output(args.output.as_deref(), &format!("{public_key}\n"))?;
        }
    }

    Ok(())
}

fn resolve_recipients(
    passphrase: Option<String>,
    passphrase_file: Option<PathBuf>,
    recipients: Vec<String>,
) -> Result<Vec<Recipient>> {
    let passphrase = resolve_optional_passphrase(passphrase, passphrase_file)?;

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
    passphrase: Option<String>,
    passphrase_file: Option<PathBuf>,
    identities: Vec<PathBuf>,
) -> Result<Vec<Identity>> {
    let passphrase = resolve_optional_passphrase(passphrase, passphrase_file)?;

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
    passphrase: Option<String>,
    passphrase_file: Option<PathBuf>,
) -> Result<Option<String>> {
    if passphrase.is_some() && passphrase_file.is_some() {
        bail!("use only one of --passphrase or --passphrase-file");
    }

    if let Some(passphrase) = passphrase {
        return Ok(Some(passphrase));
    }

    if let Some(path) = passphrase_file {
        let value = std::fs::read_to_string(&path)
            .with_context(|| format!("failed to read passphrase file {}", path.display()))?;
        return Ok(Some(value.trim_end_matches(['\r', '\n']).to_string()));
    }

    Ok(None)
}

fn write_text_output(path: Option<&str>, contents: &str) -> Result<()> {
    match path {
        Some(path) => {
            std::fs::write(path, contents).with_context(|| format!("failed to write output {path}"))
        }
        None => {
            print!("{contents}");
            Ok(())
        }
    }
}

fn open_input(path: Option<&PathBuf>) -> Result<Box<dyn Read>> {
    match path {
        Some(path) => Ok(Box::new(BufReader::new(
            File::open(path).with_context(|| format!("failed to open input {}", path.display()))?,
        ))),
        None => Ok(Box::new(BufReader::new(std::io::stdin().lock()))),
    }
}

fn open_output(path: Option<&PathBuf>) -> Result<Box<dyn Write>> {
    match path {
        Some(path) => Ok(Box::new(BufWriter::new(File::create(path).with_context(
            || format!("failed to create output {}", path.display()),
        )?))),
        None => Ok(Box::new(BufWriter::new(std::io::stdout().lock()))),
    }
}
