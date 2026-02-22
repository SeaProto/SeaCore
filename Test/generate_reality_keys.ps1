# generate_reality_keys.ps1
# Script to generate x25519 keypair and random short_ids for SeaCore REALITY

$ErrorActionPreference = "Stop"

Write-Output "Generating Realm/REALITY Keypair..."

# We can use OpenSSL or just use .NET cryptography for random bytes.
# But for standard x25519 keys, we can use an external tool if available,
# or we can use the seacore.exe command if we had built one.
# Since we don't have a built-in command in seacore for keygen,
# we will write a tiny rust program on the fly to generate it using x25519-dalek.

$tempRsPath = "keygen_temp.rs"
$tempTomlPath = "Cargo.toml"

Set-Content -Path $tempRsPath -Value @"
use x25519_dalek::{StaticSecret, PublicKey};
use rand::rngs::OsRng;
use base64::{Engine as _, engine::general_purpose::STANDARD};

fn main() {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);

    let priv_b64 = STANDARD.encode(secret.to_bytes());
    let pub_b64 = STANDARD.encode(public.as_bytes());

    let mut short_id = [0u8; 8];
    rand::RngCore::fill_bytes(&mut OsRng, &mut short_id);
    let short_id_hex = hex::encode(short_id);

    println!("[Private Key (server.json)]: {}", priv_b64);
    println!("[Public Key  (client.json)]: {}", pub_b64);
    println!("[Short ID   (both json)]: {}", short_id_hex);
}
"@

Write-Output "Building temporary keygen tool..."
# Create a temporary cargo project
$tempDir = Join-Path $PWD "temp_keygen"
if (Test-Path $tempDir) { Remove-Item -Recurse -Force $tempDir }
New-Item -ItemType Directory -Path $tempDir | Out-Null
Set-Location $tempDir

# Initialize cargo
cargo init --bin | Out-Null
Set-Content -Path "Cargo.toml" -Value @"
[package]
name = "temp_keygen"
version = "0.1.0"
edition = "2021"

[dependencies]
x25519-dalek = { version = "2.0", features = ["static_secrets"] }
rand = "0.8"
base64 = "0.22"
hex = "0.4"
"@
Copy-Item "..\$tempRsPath" "src\main.rs"

Write-Output "Running keygen..."
Write-Output "----------------------------------------------------"
cargo run --release -q
Write-Output "----------------------------------------------------"

Set-Location ..
Remove-Item -Recurse -Force $tempDir
Remove-Item -Force $tempRsPath

Write-Output "Cleanup complete. Use these values to update your Test/server.json and Test/client.json."
