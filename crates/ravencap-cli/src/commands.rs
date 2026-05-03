use anyhow::{Context, Result};
use ravencap_core::{EncryptOptions, PackOptions, UnpackOptions, VerifyMode};

use crate::cli::{Cli, Command};
use crate::output::{
    open_command_input, open_input, with_output, write_inspect_report, write_public_info,
    write_text_output, write_verify_report,
};
use crate::secrets::{resolve_identities, resolve_recipients};

pub(crate) fn run(cli: Cli) -> Result<()> {
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
