#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT_PATH="${ROOT_DIR}/Test/test_matrix.py"

cd "${ROOT_DIR}"

echo "Building release binary..."
cargo build --release -p seacore

if command -v python3 >/dev/null 2>&1; then
  python3 "${SCRIPT_PATH}" "$@"
else
  python "${SCRIPT_PATH}" "$@"
fi
