mod cli;
mod commands;
mod output;
mod secrets;

use anyhow::Result;
use clap::Parser;

fn main() -> Result<()> {
    commands::run(cli::Cli::parse())
}
