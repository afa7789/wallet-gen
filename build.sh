#!/usr/bin/env bash
# Gera o executável one-file (GUI + CLI) para o SO atual: dist/wallet-gen[.exe]
# Mesmo script local e no CI (macOS, Linux, Windows via Git Bash). Deps vêm do wallet_gen.py.lock.
set -euo pipefail
cd "$(dirname "$0")"
uv export --script wallet_gen.py --no-hashes --quiet > build-requirements.txt
uv run --python 3.12 --no-project --with-requirements build-requirements.txt --with pyinstaller==6.22.3 \
  pyinstaller --onefile --clean --noconfirm --name wallet-gen \
  --copy-metadata bip_utils --copy-metadata coincurve --copy-metadata PyNaCl --copy-metadata pycryptodome \
  --collect-data bip_utils --collect-all coincurve --collect-all nacl \
  wallet_gen.py
rm -f build-requirements.txt
ls -la dist/
