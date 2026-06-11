#!/usr/bin/env bash
# Builds a clean, store-ready extension zip containing only the files Chrome
# loads — excluding docs, server, tests, scripts, and dev tooling.
set -euo pipefail

cd "$(dirname "$0")/.."
OUT_DIR="dist"
OUT="$OUT_DIR/canadian-scam-shield.zip"

mkdir -p "$OUT_DIR"
rm -f "$OUT"

# Only the runtime files the extension needs.
INCLUDE=(
  manifest.json
  background
  content
  lib
  popup
  options
  warning
  onboarding
  data
  icons
)

# Sanity: every include path must exist.
for p in "${INCLUDE[@]}"; do
  [ -e "$p" ] || { echo "missing: $p" >&2; exit 1; }
done

# Exclude any stray dev files that might live under included dirs.
zip -r -q "$OUT" "${INCLUDE[@]}" \
  -x '*/.DS_Store' '*/node_modules/*' '*.map'

echo "Built $OUT"
unzip -l "$OUT" | tail -n 1
