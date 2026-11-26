# Cowrie: Pitch & Positioning

> **Cowrie is an independent federated Cashu mint where a Move smart contract, not the guardians, keeps the ledger and holds the reserves.**
>
> *Signed by a federation. Kept by a contract.*

This is the source of truth for how Cowrie is described: the landing page, the playground copy, the submission text and the demo video all follow it.

---

## 1. What Cowrie does differently

Cowrie follows Cashu's federated-mint design (t-of-n guardians, blind BLS signatures) and changes *where consensus and custody live*. Verified against `cashu/move/cowrie_cashu/sources/mint_vault.move` and `blind-seal/`:

| Job | Single Cashu mint | Federated Cashu (typical) | **Cowrie** |
|---|---|---|---|
| **Signing key** | 1 operator | t-of-n guardians | t-of-n guardians, dealer-free Pedersen DKG |
| **Consensus** (who spent what, in what order) | operator's database | a consensus system the guardians run together | **Move contract on Sui.** The `spent_ys` nullifier table is ordered by Sui. Guardians run no consensus. |
| **Custody** (where reserves sit) | operator's Lightning node | held by the federation | **`MintVault<Asset>` shared object** (`Balance<Asset>`: USDC, LBTC, SUI, …) |
| **Proof of reserves** | trust the operator | trust the federation | **Live on-chain** (`vault_reserve_value`) |
| **Redemption** | operator must agree to pay | federation must agree to pay | **Permissionless:** `melt_native_dst` verifies BLS notes on-chain and pays out |
| **Issuance gate** | operator decides | federation decides | Guardians sign only `BlindSigningTicket`s that already exist on-chain |
| **If key holders collude** | everything is lost | everything is lost | **Damage is bounded:** the hourly melt cap (`EMeltCircuitBreakerTripped`) limits how much leaves per hour |
| **Guardian operations** | — | run consensus nodes | stateless signers that check tickets and return shares |

> Phrase comparisons as "instead of guardians running consensus", never as a criticism of the reference design.

**Why BLS makes this possible:** a secp256k1 Cashu note can only be checked by the mint that signed it. A BLS12-381 note can be checked by anyone, including a smart contract. That is what lets the contract pay out notes without asking the guardians, and why 500 streamed notes can settle in one transaction (one pairing per denomination used).

**The same binary also runs standalone** on Lightning (`EmbeddedMoveEngine` + LNbits) for operators who don't want an on-chain vault.

---

## 2. Short versions

- **Tagline:** Signed by a federation. Kept by a contract.
- **One sentence:** Cowrie is a federated Cashu mint where a Move smart contract, not the guardians, keeps the ledger and holds the reserves: anyone can audit it, anyone can redeem, and there's a hard cap on how fast funds can leave.
- **30 seconds (spoken):** "Every Cashu mint has a keeper: one key, one chest. Cowrie gives the chest to a Move smart contract. It keeps the ledger, holds the reserves in plain sight, and pays any valid note itself. If guardians lie, they're caught; if they conspire, the vault releases only so much each hour. Cowrie: signed by a federation, kept by a contract."

---

## 3. Demo video narration

The video ("The Lighthouse Coast", ~1:52, storybook illustration with narration) is produced outside this repository. Its narration, page by page:

| Page | Narration |
|---|---|
| 1 · Once | Long ago, along the Indian Ocean, people paid each other in cowrie shells. Small, hard to fake, easy to carry. |
| 2 · Cashu | Cashu brought that idea back as ecash: private, instant, in your pocket. |
| 3 · The keeper | But every Cashu mint has a keeper. One key, one chest. If the keeper sails off, the shells sail with them. |
| 4 · Five lighthouses | Federated Cashu shares the key among five guardians. Any four can sign; none can sign alone. But the guardians still keep the ledger, and still guard the chest. |
| 5 · The harbor vault | Cowrie gives both jobs to a Move smart contract. The contract keeps the ledger of spent notes, so no shell is ever spent twice. It holds the reserves in plain sight, for anyone to count. And it pays out any valid note itself. No one can refuse your withdrawal. |
| 6 · The storm | If a guardian shows a false light, its forged share is caught. If too many go dark, signing stops safely. And even if guardians conspire, the vault releases only so much each hour. |
| 7 · Why it works | This works because Cowrie signs with BLS, a signature a smart contract can check on its own. Five hundred streamed sats settle in a single transaction. |
| 8 · An independent mint | Cowrie is an independent implementation of Cashu's federated mint, written from scratch in Rust and Move. It speaks the Cashu API, with a different foundation underneath. |
| 9 · The end | Cowrie. Signed by a federation, kept by a contract. |

**Visual language (used by the landing page and playground too):** the Lighthouse Coast. Guardians are lighthouses around a bay; the Move contract is a stone harbor vault lettered MINT VAULT; a forged share is a wrecker's false light; an offline guardian is a dark lighthouse; the hourly cap is an hourglass. Palette: night `#1F2A44`, bay `#2F6669`, parchment `#F2E6CF`, lamplight `#E9B44C`, wrecker red `#C8553D`, driftwood `#7A4E2F`. Type: Fraunces (titles), Literata (text), JetBrains Mono (protocol).

---

## 4. Q&A prep (judges will ask)

| Question | Honest answer |
|---|---|
| *Can 4 colluding guardians still steal?* | They can sign notes with no deposit behind them and try to redeem them. The hourly melt cap bounds the loss per hour, and every melt is public on-chain, so a drain is visible as it happens. A bounded, visible risk instead of an instant, silent one. |
| *Isn't on-chain bad for privacy?* | Issuance is blinded, so a deposit can't be linked to a later spend. Notes pass between people off-chain as bearer tokens. In Sui mode, swaps and melts are public transactions: amounts and nullifiers are visible, not who received which note. |
| *Why Sui and not Bitcoin?* | Sui has native BLS12-381 pairings in Move, so the contract can verify notes itself. Assets include LBTC (bitcoin on Sui), USDC and SUI. For a Bitcoin-only setup, the same `cowried` binary runs standalone with Lightning. |
| *Does it work with existing Cashu wallets?* | It speaks the Cashu NUT API, but keysets are BLS12-381 and current wallets only support secp256k1 keysets. Cowrie ships its own WASM and CLI wallets; [`federated-bls-spec-notes.md`](federated-bls-spec-notes.md) proposes a standard for BLS keysets. |
| *What if Sui halts?* | Redemptions pause until Sui recovers. Notes still pass between people offline, and nothing can be double-spent while the ledger is stopped. |
| *Smart contract risk?* | The `mint_vault` Move tests cover double-spend, slot inflation, rogue batch forgery and the circuit breaker. It is unaudited hackathon code; say so. |
