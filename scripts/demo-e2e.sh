#!/usr/bin/env bash
# One-command End-to-End Smoke Demo for Cowrie (4-of-5 BLS12-381 Federated Cashu Mint + CLI Wallet).
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PORT="${COWRIE_PORT:-3348}"
TMP_DIR="$(mktemp -d)"
MINT_PID=""

cleanup() {
  if [[ -n "$MINT_PID" ]]; then
    kill "$MINT_PID" 2>/dev/null || true
    wait "$MINT_PID" 2>/dev/null || true
  fi
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

echo "==> [1/7] Building cowried and cowrie-cli..."
cargo build --manifest-path "$ROOT_DIR/Cargo.toml" -p cowrie-cashu-mintd --bins --quiet

COWRIED="$ROOT_DIR/target/debug/cowried"
CLI="$ROOT_DIR/target/debug/cowrie-cli"
WALLET="$TMP_DIR/wallet.json"
MINT_URL="http://127.0.0.1:$PORT"

echo "==> [2/7] Starting 4-of-5 Federated Cashu Mint (cowried) on $MINT_URL..."
"$COWRIED" --bind "127.0.0.1:$PORT" --data-dir "$TMP_DIR/mint-data" >"$TMP_DIR/cowried.log" 2>&1 &
MINT_PID=$!

for _ in $(seq 1 30); do
  if curl -sf "$MINT_URL/v1/info" >/dev/null 2>&1; then
    break
  fi
  sleep 0.25
done

echo "==> [3/7] Querying NUT-06 /v1/info & NUT-13 deterministic seed..."
"$CLI" --mint-url "$MINT_URL" --wallet "$WALLET" info | head -n 12
SEED_LINE="$("$CLI" --mint-url "$MINT_URL" --wallet "$WALLET" seed)"
echo "    $SEED_LINE"

echo "==> [4/7] Minting 64 sat via two-step NUT-23 bolt11 quote (4-of-5 BLS12-381)..."
"$CLI" --mint-url "$MINT_URL" --wallet "$WALLET" mint 64
"$CLI" --mint-url "$MINT_URL" --wallet "$WALLET" balance

echo "==> [5/7] Exporting 16 sat as compact NUT-00 V4 binary CBOR (cashuB...) and swapping back..."
TOKEN="$("$CLI" --mint-url "$MINT_URL" --wallet "$WALLET" send 16)"
echo "    Token (${#TOKEN} chars): ${TOKEN:0:64}..."
"$CLI" --mint-url "$MINT_URL" --wallet "$WALLET" receive "$TOKEN"
"$CLI" --mint-url "$MINT_URL" --wallet "$WALLET" checkstate

echo "==> [6/7] Simulating wallet wipe & restoring 100% of unspent sats via NUT-13 + NUT-09..."
SEED_VAL="${SEED_LINE#NUT-13 Recovery Seed: }"
rm -f "$WALLET"
"$CLI" --mint-url "$MINT_URL" --wallet "$WALLET" restore --seed "$SEED_VAL"
"$CLI" --mint-url "$MINT_URL" --wallet "$WALLET" balance

echo "==> [7/7] Melting 64 sat back via NUT-05 bolt11..."
"$CLI" --mint-url "$MINT_URL" --wallet "$WALLET" melt 64 lnbc64sat1p_cowrie_smoke_test
"$CLI" --mint-url "$MINT_URL" --wallet "$WALLET" balance

echo ""
echo "PASS: Full 4-of-5 BLS12-381 Mint -> Swap -> NUT-07 -> NUT-13/09 Restore -> Melt verified!"
