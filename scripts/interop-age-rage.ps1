param(
    [string]$Vector = "tests/vectors/archive-public-key.rav",
    [string]$Identity = "tests/vectors/identity/alice.ravkey"
)

$ErrorActionPreference = "Stop"

function Test-RavpPlaintext {
    param([string]$Path)

    $bytes = [System.IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -lt 5) {
        throw "decrypted plaintext is too short: $Path"
    }

    $magic = [System.Text.Encoding]::ASCII.GetString($bytes, 0, 4)
    if ($magic -ne "RAVP" -or $bytes[4] -ne 0) {
        throw "decrypted plaintext does not start with RAVP magic: $Path"
    }
}

$temp = Join-Path ([System.IO.Path]::GetTempPath()) ("ravencap-interop-" + [System.Guid]::NewGuid())
New-Item -ItemType Directory -Path $temp | Out-Null

try {
    foreach ($binary in @("age", "rage")) {
        $command = Get-Command $binary -ErrorAction SilentlyContinue
        if ($null -eq $command) {
            Write-Host "$binary not found; skipping"
            continue
        }

        $output = Join-Path $temp "$binary.ravp"
        & $command.Source --decrypt --identity $Identity --output $output $Vector
        if ($LASTEXITCODE -ne 0) {
            throw "$binary failed to decrypt $Vector"
        }

        Test-RavpPlaintext $output
        Write-Host "$binary decrypted $Vector to RAVP plaintext"
    }
}
finally {
    Remove-Item -Recurse -Force $temp -ErrorAction SilentlyContinue
}