use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

#[derive(Parser)]
#[command(name = "ravencap", version, about = "Streaming encrypted archive tool")]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Subcommand)]
pub(crate) enum Command {
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
pub(crate) struct PathCommand {
    pub(crate) input: String,

    #[arg(short, long)]
    pub(crate) output: Option<PathBuf>,

    #[arg(long)]
    pub(crate) overwrite: bool,
}

#[derive(Args)]
pub(crate) struct PackCommand {
    pub(crate) input: PathBuf,

    #[arg(short, long)]
    pub(crate) output: Option<PathBuf>,

    #[arg(long)]
    pub(crate) overwrite: bool,

    #[arg(long = "insecure-passphrase-cli")]
    pub(crate) insecure_passphrase_cli: Option<String>,

    #[arg(long)]
    pub(crate) passphrase_file: Option<PathBuf>,

    #[arg(short = 'r', long = "recipient")]
    pub(crate) recipients: Vec<String>,
}

#[derive(Args)]
pub(crate) struct UnpackCommand {
    pub(crate) input: String,

    #[arg(short, long)]
    pub(crate) output: PathBuf,

    #[arg(long = "insecure-passphrase-cli")]
    pub(crate) insecure_passphrase_cli: Option<String>,

    #[arg(long)]
    pub(crate) passphrase_file: Option<PathBuf>,

    #[arg(long = "identity")]
    pub(crate) identities: Vec<PathBuf>,
}

#[derive(Args)]
pub(crate) struct CryptoCommand {
    #[arg(short, long)]
    pub(crate) input: Option<PathBuf>,

    #[arg(short, long)]
    pub(crate) output: Option<PathBuf>,

    #[arg(long)]
    pub(crate) overwrite: bool,

    #[arg(long = "insecure-passphrase-cli")]
    pub(crate) insecure_passphrase_cli: Option<String>,

    #[arg(long)]
    pub(crate) passphrase_file: Option<PathBuf>,

    #[arg(short = 'r', long = "recipient")]
    pub(crate) recipients: Vec<String>,

    #[arg(long = "identity")]
    pub(crate) identities: Vec<PathBuf>,
}

#[derive(Args)]
pub(crate) struct VerifyCommand {
    pub(crate) input: String,

    #[arg(long)]
    pub(crate) quick: bool,

    #[arg(long)]
    pub(crate) json: bool,

    #[arg(long = "insecure-passphrase-cli")]
    pub(crate) insecure_passphrase_cli: Option<String>,

    #[arg(long)]
    pub(crate) passphrase_file: Option<PathBuf>,

    #[arg(long = "identity")]
    pub(crate) identities: Vec<PathBuf>,
}

#[derive(Args)]
pub(crate) struct InspectCommand {
    pub(crate) input: String,

    #[arg(short, long)]
    pub(crate) output: Option<PathBuf>,

    #[arg(long)]
    pub(crate) overwrite: bool,

    #[arg(long)]
    pub(crate) json: bool,

    #[arg(long = "insecure-passphrase-cli")]
    pub(crate) insecure_passphrase_cli: Option<String>,

    #[arg(long)]
    pub(crate) passphrase_file: Option<PathBuf>,

    #[arg(long = "identity")]
    pub(crate) identities: Vec<PathBuf>,
}

#[derive(Args)]
pub(crate) struct OutputCommand {
    #[arg(short, long)]
    pub(crate) output: Option<PathBuf>,

    #[arg(long)]
    pub(crate) overwrite: bool,
}
