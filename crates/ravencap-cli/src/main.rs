use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::PathBuf;

use anyhow::{Context, Result};
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
            let passphrase = resolve_passphrase(args.passphrase, args.passphrase_file)?;
            let output = open_output(args.output.as_ref())?;
            let options = PackOptions::passphrase(passphrase);
            ravencap_core::pack_path(args.input, output, options)?;
        }
        Command::Unpack(args) => {
            println!("unpack scaffold ready for input {}", args.input);
        }
        Command::Encrypt(args) => {
            let passphrase = resolve_passphrase(args.passphrase, args.passphrase_file)?;
            let input = open_input(args.input.as_ref())?;
            let output = open_output(args.output.as_ref())?;
            let options = EncryptOptions::new().recipient(Recipient::passphrase(passphrase));
            ravencap_core::encrypt_stream(input, output, options)?;
        }
        Command::Decrypt(args) => {
            let passphrase = resolve_passphrase(args.passphrase, args.passphrase_file)?;
            let input = open_input(args.input.as_ref())?;
            let output = open_output(args.output.as_ref())?;
            ravencap_core::decrypt_stream(input, output, vec![Identity::passphrase(passphrase)])?;
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
            println!("keygen scaffold ready; output {:?}", args.output);
        }
        Command::Pubkey(args) => {
            println!("pubkey scaffold ready for input {}", args.input);
        }
    }

    Ok(())
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

fn resolve_passphrase(
    passphrase: Option<String>,
    passphrase_file: Option<PathBuf>,
) -> Result<String> {
    if let Some(passphrase) = passphrase {
        return Ok(passphrase);
    }

    if let Some(path) = passphrase_file {
        let value = std::fs::read_to_string(&path)
            .with_context(|| format!("failed to read passphrase file {}", path.display()))?;
        return Ok(value.trim_end_matches(['\r', '\n']).to_string());
    }

    rpassword::prompt_password("Passphrase: ").context("failed to read passphrase")
}
