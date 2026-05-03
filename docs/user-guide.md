# Simple User Guide

This guide is for people who want to use Ravencap without learning the technical details.

## What Ravencap Does

Ravencap makes encrypted `.rav` files. You can use it to lock a file or folder, check that an encrypted archive is valid, and restore the original contents later.

Keep two things safe:

- Your `.rav` encrypted archive.
- Your passphrase or private key.

If you lose the passphrase or private key, Ravencap cannot recover the files.

## Before You Start

Install Ravencap and open a terminal in the folder where your files are. On Windows, PowerShell is fine.

### Install Ravencap

Ravencap is a command-line app. That means you run it from a terminal, not by double-clicking an icon.

The easiest install method depends on what the project provides for your computer. If there is a ready-made download on the GitHub Releases page, use that first:

1. Open the Ravencap releases page.
2. Download the file for your operating system.
3. Unzip it if needed.
4. Put the `ravencap` or `ravencap.exe` file somewhere easy to find, such as a `Ravencap` folder in your user directory.
5. Open a terminal in that folder and run `ravencap --help`.

If there is no ready-made download yet, install it from source with Rust:

1. Install Rust from `https://rustup.rs/`.
2. Download the Ravencap source code from GitHub and unzip it.
3. Open a terminal inside the unzipped Ravencap folder.
4. Build Ravencap:

```sh
cargo build --release
```

After the build finishes, the program will be here:

- Windows: `target\release\ravencap.exe`
- macOS/Linux: `target/release/ravencap`

You can run it from the project folder like this:

```sh
target\release\ravencap.exe --help
```

On macOS or Linux, use:

```sh
./target/release/ravencap --help
```

For regular use, copy the built program to the folder where you keep your tools, or keep using it from the `target/release` folder.

Check that Ravencap runs:

```sh
ravencap --help
```

For the simplest workflow, put your passphrase in a small text file named `passphrase.txt`:

```text
use-a-long-private-passphrase-here
```

Do not share this file. Do not upload it next to your encrypted archives.

## Encrypt A Folder

This creates `photos.rav` from a folder named `photos`:

```sh
ravencap pack --passphrase-file passphrase.txt photos -o photos.rav
```

After this succeeds, `photos.rav` is the encrypted archive. Keep it somewhere safe.

## Check An Archive

Before deleting, moving, or restoring from an archive, check it:

```sh
ravencap verify photos.rav --passphrase-file passphrase.txt
```

If the command succeeds, Ravencap was able to decrypt the archive and verify its contents.

## Restore A Folder

This restores `photos.rav` into a new folder named `restored-photos`:

```sh
ravencap unpack photos.rav --passphrase-file passphrase.txt -o restored-photos
```

The output folder must not already exist. Choose a new folder name each time.

## Encrypt One File

For a normal file, you can also use `encrypt` and `decrypt`:

```sh
ravencap encrypt --passphrase-file passphrase.txt -i document.pdf -o document.pdf.rav
ravencap decrypt --passphrase-file passphrase.txt -i document.pdf.rav -o document-restored.pdf
```

Use `pack` and `unpack` for folders. Use `encrypt` and `decrypt` for single files or simple data streams.

## Safer Habits

- Use a long passphrase that is not used anywhere else.
- Store `passphrase.txt` separately from your `.rav` archives.
- Run `ravencap verify` after creating an important archive.
- Restore to a new folder and check the files before deleting originals.
- Do not type secrets directly in the command line.

Ravencap has an option named `--insecure-passphrase-cli`, but it is for controlled testing only. Normal users should use `--passphrase-file` or the interactive prompt.

## Common Problems

If Ravencap says the output already exists, choose a different output name or use `--overwrite` only when you are sure you want to replace that file.

If Ravencap cannot decrypt an archive, check that you are using the right passphrase file or private key.

If you are restoring a folder, make sure the output folder name does not already exist.
