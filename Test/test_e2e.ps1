$ErrorActionPreference = "Stop"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$matrixScript = Join-Path $PSScriptRoot "test_matrix.py"

Push-Location $repoRoot
try {
    Write-Host "Building release binary..."
    cargo build --release -p seacore

    $py = Get-Command py -ErrorAction SilentlyContinue
    if ($py) {
        & py -3 $matrixScript @args
    } else {
        & python $matrixScript @args
    }

    if ($LASTEXITCODE -ne 0) {
        throw "SeaCore matrix failed with exit code $LASTEXITCODE"
    }
}
finally {
    Pop-Location
}
