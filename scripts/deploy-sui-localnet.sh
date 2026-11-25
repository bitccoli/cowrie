#!/usr/bin/env bash
# End-to-end deployment helper for publishing `blind_seal` + `cowrie_cashu` to a running
# `sui start` localnet (or Sui Testnet) and starting `cowried` backed by the live Move `MintVault`.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SUI_RPC="${SUI_RPC:-http://127.0.0.1:9000}"
DATA_DIR="${DATA_DIR:-$ROOT_DIR/cowrie-sui-live}"

echo "==> [1/4] Publishing blind-seal/move/blind_seal on $SUI_RPC ..."
BS_JSON="$(sui client publish "$ROOT_DIR/blind-seal/move/blind_seal" --gas-budget 100000000 --json)"
BLIND_SEAL_PKG="$(echo "$BS_JSON" | jq -r '.objectChanges[] | select(.type == "published") | .packageId')"
echo "    blind_seal package: $BLIND_SEAL_PKG"

echo "==> [2/4] Publishing cashu/move/cowrie_cashu on $SUI_RPC ..."
CC_JSON="$(sui client publish "$ROOT_DIR/cashu/move/cowrie_cashu" --gas-budget 100000000 --json)"
COWRIE_CASHU_PKG="$(echo "$CC_JSON" | jq -r '.objectChanges[] | select(.type == "published") | .packageId')"
echo "    cowrie_cashu package: $COWRIE_CASHU_PKG"

echo "==> [3/4] Generating 4-of-5 Pedersen DKG keyset in $DATA_DIR ..."
mkdir -p "$DATA_DIR"
cargo run --manifest-path "$ROOT_DIR/Cargo.toml" -p blind-seal-server -- pedersen-dkg \
  --keyset-id 02cowriesui00001 \
  --unit usd \
  --threshold 4 \
  --peers 5 \
  --slots 16 \
  --out-dir "$DATA_DIR/dkg"

ACTIVE_ADDR="$(sui client active-address)"
PRIVKEY="$(sui keytool export --key-identity "$ACTIVE_ADDR" --json | jq -r '.exportedPrivateKey')"

echo "==> [4/4] Registering KeysetInfo & shared MintVault<0x2::sui::SUI> on Sui ..."
PKS_JSON="$(jq -c '[.slot_agg_pks[] | ("0x" + .)]' "$DATA_DIR/dkg/public_keyset.json")"
IBE_HEX="0x$(jq -r '.ibe_agg_pk_g1' "$DATA_DIR/dkg/public_keyset.json")"

REG_JSON="$(sui client ptb \
  --move-call "${BLIND_SEAL_PKG}::blind_seal::register_keyset" \
    "\"02cowriesui00001\"" "\"usd\"" 4u16 5u16 "vector${PKS_JSON}" "${IBE_HEX}" \
  --assign cap \
  --move-call "${COWRIE_CASHU_PKG}::mint_vault::create_vault" "<0x2::sui::SUI>" \
    cap "\"02cowriesui00001\"" 1u64 10000000u64 \
  --gas-budget 100000000 \
  --json)"

KEYSET_INFO_ID="$(echo "$REG_JSON" | jq -r '.objectChanges[] | select(.objectType | endswith("::blind_seal::KeysetInfo")) | .objectId')"
VAULT_OBJECT_ID="$(echo "$REG_JSON" | jq -r '.objectChanges[] | select(.objectType | contains("::mint_vault::MintVault")) | .objectId')"

echo "    KeysetInfo:   $KEYSET_INFO_ID"
echo "    MintVault:    $VAULT_OBJECT_ID"
echo ""
echo "==> Launching cowried connected to live Sui MintVault ..."
exec cargo run --manifest-path "$ROOT_DIR/Cargo.toml" -p cowrie-cashu-mintd --bin cowried -- \
  --bind 127.0.0.1:3338 \
  --data-dir "$DATA_DIR" \
  --sui-rpc "$SUI_RPC" \
  --blind-seal-package-id "$BLIND_SEAL_PKG" \
  --cowrie-package-id "$COWRIE_CASHU_PKG" \
  --vault-object-id "$VAULT_OBJECT_ID" \
  --keyset-info-id "$KEYSET_INFO_ID" \
  --sui-asset-type "0x2::sui::SUI" \
  --sui-private-key "$PRIVKEY"
