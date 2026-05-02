# Examples

These examples use commands covered by integration tests or note their external dependency. Replace sample filenames, passphrases, and keys before using them with real data.

Password-mode raw stream encryption:

```sh
ravencap encrypt --passphrase-file passphrase.txt -i payload.ravp -o payload.rav
ravencap decrypt --passphrase-file passphrase.txt -i payload.rav -o payload.ravp
```

Password-mode archive pack, inspect, verify, and unpack:

```sh
ravencap pack --passphrase-file passphrase.txt ./folder -o folder.rav
ravencap inspect folder.rav --passphrase-file passphrase.txt
ravencap verify folder.rav --passphrase-file passphrase.txt
ravencap unpack folder.rav --passphrase-file passphrase.txt -o restored-folder
```

Public-key archive pack and unpack:

```sh
ravencap keygen -o alice.ravkey
ravencap pubkey alice.ravkey -o alice.ravpub
ravencap pack -r $(cat alice.ravpub) ./folder -o folder.rav
ravencap unpack folder.rav --identity alice.ravkey -o restored-folder
```

Inspect JSON and quick/full verification:

```sh
ravencap inspect folder.rav --passphrase-file passphrase.txt --json
ravencap verify --quick folder.rav --passphrase-file passphrase.txt
ravencap verify folder.rav --passphrase-file passphrase.txt --json
```

Stdin and stdout pipeline usage for raw streams:

```sh
ravencap encrypt --passphrase-file passphrase.txt < payload.ravp > payload.rav
ravencap decrypt --passphrase-file passphrase.txt < payload.rav > payload.ravp
```

Age/rage interop smoke check for the public-key vector:

```powershell
./scripts/interop-age-rage.ps1
```

The script is optional and skips whichever of `age` or `rage` is not installed.

Reading archive input from stdin:

```sh
ravencap verify --quick - --passphrase-file passphrase.txt < folder.rav
ravencap inspect - --passphrase-file passphrase.txt --json < folder.rav
```

Managed outputs and shell redirection:

```sh
ravencap decrypt --passphrase-file passphrase.txt -i payload.rav -o payload.ravp --overwrite
ravencap decrypt --passphrase-file passphrase.txt < payload.rav > payload.ravp
```

The `-o` form is managed by Ravencap and writes through a same-directory temporary file. The redirected form is managed by the shell and can leave a partial output file if the command is interrupted or fails after the shell creates the destination.

Hardware-key or plugin-backed age workflows:

```sh
age -d -i plugin-or-hardware-backed-identity folder.rav > folder.ravp
```

Ravencap `.rav` files are age-compatible at the outer encryption layer. The Ravencap CLI does not invoke age plugins directly in v1; use external age-compatible tooling to produce RAVP plaintext, then use Ravencap semantics where supported by Ravencap commands.
