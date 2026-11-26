# Cowrie: Hackathon Submission (Nut November 2026)

## Project title
**Cowrie**: an independent federated Cashu mint with a Move smart-contract vault

## Tagline
Signed by a federation. Kept by a contract.

## One-liner
Cowrie is a federated Cashu mint where a Move smart contract, not the guardians, keeps the ledger and holds the reserves: anyone can audit it, anyone can redeem, and there's a hard cap on how fast funds can leave.

## Links
- **Repository:** https://github.com/bitccoli/cowrie
- **Live landing page & playground:** https://cowrie-cashu.fly.dev (playground: https://cowrie-cashu.fly.dev/playground)
- **Demo video:** *(add the YouTube / Devpost link)*
- **Judge walkthrough:** [hackathon-walkthrough.md](hackathon-walkthrough.md)
- **Pitch, comparison table & Q&A:** [pitch.md](pitch.md)
- **Protocol spec notes (proposed NUT-BLS):** [federated-bls-spec-notes.md](federated-bls-spec-notes.md)

---

## Submission description (ready to paste)

### The problem
Every Cashu mint today is one operator holding one key and one pot of reserves. If the operator disappears, so do the users' sats. Federated Cashu spreads the signing key across t-of-n guardians, but the guardians still have to agree on which notes were spent and still hold the reserves between them.

### What Cowrie does
Cowrie keeps Cashu's federated signing (4-of-5 threshold BLS12-381, dealer-free Pedersen DKG) and hands **consensus and custody** to a **Move smart contract on Sui** (`cowrie_cashu::mint_vault`):

- **Consensus:** the contract keeps the table of spent notes (48-byte `Y` nullifiers), ordered by Sui, so no note is spent twice. Guardians don't run their own consensus.
- **Custody:** reserves sit in a `MintVault<Asset>` shared object. Anyone can read the balance on-chain at any time.
- **Permissionless redemption:** `melt_native_dst` verifies the BLS notes on-chain (slot-grouped multi-pairing with 120-bit Fiat-Shamir weights) and pays out. No operator can refuse a withdrawal.
- **Issuance gate:** guardians sign only `BlindSigningTicket`s that already exist on-chain, after a deposit or swap is recorded.
- **Bounded damage:** an hourly melt circuit breaker caps how much can leave the vault, even if guardians collude.

It works because BLS signatures can be verified by anyone, including a smart contract. The same `cowried` binary also runs standalone on Lightning (embedded engine + LNbits) for operators who don't want an on-chain vault.

### Built and shown
- **`cowried` mint:** Cashu NUT REST API (NUT-00 V4 `cashuB`, 01–07, 09–14, 17 WebSocket, 23, 24 HTTP-402) over a 4-of-5 guardian federation.
- **Live playground:** a non-custodial browser wallet (WASM blinding and offline pairing checks, NUT-13 seed restore) where you can make a guardian forge shares (caught by pairing checks) or go offline (issuance halts safely), and stream 1 sat/second over HTTP-402.
- **Move packages:** `blind_seal` and `cowrie_cashu` with VM tests for double-spend, slot inflation, rogue batch forgery and the circuit breaker.
- **Spec notes:** pitfalls found while building independently, including why linear per-denomination key tweaks let anyone forge a 1,024-sat note from a 1-sat note.

### Measured (`cowrie-bench --release`)
- **48-byte** signatures with no DLEQ needed: 256-note tokens are **32.6% smaller** than secp256k1 + NUT-12 DLEQ.
- **256 notes** batch-verify in **63.7 ms** with 2 pairings (vs 306.7 ms one by one).
- Single-note offline verify: **1.21 ms**.

### Honest limits
Unaudited hackathon code. Current Cashu wallets only support secp256k1 keysets, so Cowrie ships its own wallets. In Sui mode, swaps and melts are public on-chain transactions (issuance stays blinded). See the Q&A in [pitch.md](pitch.md).
