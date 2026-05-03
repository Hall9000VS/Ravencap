# Fuzzing

This directory contains cargo-fuzz/libFuzzer harnesses for untrusted Ravencap input boundaries.

Targets:

- `ravp_prelude_parser`: parses arbitrary bytes as an RAVP prelude prefix.
- `manifest_parser`: parses arbitrary bytes as both format-level and core archive manifests.
- `archive_path_validator`: validates archive paths and `link_path\0target` symlink target pairs.
- `tar_entry_path_validator`: parses arbitrary bytes as a TAR stream and validates discovered entry paths.

Build all harnesses without running fuzzing:

```sh
cargo check --manifest-path fuzz/Cargo.toml --bins
```

Run a target with cargo-fuzz:

```sh
cargo +nightly fuzz run ravp_prelude_parser
```

Run only the checked-in corpus for a target:

```sh
cargo +nightly fuzz run ravp_prelude_parser fuzz/corpus/ravp_prelude_parser -- -runs=0
```

Run all checked-in corpora as smoke tests:

```powershell
cargo +nightly fuzz run ravp_prelude_parser fuzz/corpus/ravp_prelude_parser -- -runs=0
cargo +nightly fuzz run manifest_parser fuzz/corpus/manifest_parser -- -runs=0
cargo +nightly fuzz run archive_path_validator fuzz/corpus/archive_path_validator -- -runs=0
cargo +nightly fuzz run tar_entry_path_validator fuzz/corpus/tar_entry_path_validator -- -runs=0
```

## Windows MSVC Sanitizer Runtime

On Windows MSVC, `cargo-fuzz` needs the x64 AddressSanitizer runtime libraries on `LIB` and the matching runtime DLL directory on `PATH`. If `cargo +nightly fuzz run ...` fails with a missing `clang_rt.asan_dynamic_runtime_thunk-x86_64.lib`, find the installed x64 ASAN runtime and add it to your user environment.

Example PowerShell setup using the Visual Studio toolset layout:

```powershell
$asanLib = "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Tools\MSVC\14.44.35207\lib\x64"
$asanBin = "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64"

$env:LIB = "$asanLib;$env:LIB"
$env:PATH = "$asanBin;$env:PATH"
```

To persist those paths for new PowerShell sessions:

```powershell
$userLib = [Environment]::GetEnvironmentVariable('LIB', 'User')
$libParts = @($userLib -split ';' | Where-Object { $_ })
if ($libParts -notcontains $asanLib) {
    [Environment]::SetEnvironmentVariable('LIB', (($libParts + $asanLib) -join ';'), 'User')
}

$userPath = [Environment]::GetEnvironmentVariable('PATH', 'User')
$pathParts = @($userPath -split ';' | Where-Object { $_ })
if ($pathParts -notcontains $asanBin) {
    [Environment]::SetEnvironmentVariable('PATH', (($pathParts + $asanBin) -join ';'), 'User')
}
```

After updating persistent environment variables, open a new terminal or set `$env:LIB` and `$env:PATH` in the current one before running `cargo +nightly fuzz run`.

Seed corpora live under `fuzz/corpus` and cover invalid magic, unsupported version, oversized manifest length, truncated prefix, invalid JSON, duplicate paths, traversal paths, unsafe symlinks, and non-TAR input.
