# Specification & Engineering Notes: Implementing Federated Cashu (`BLS12-381`) Independently

While building **Cowrie**—an independent clean-room Rust implementation of $t$-of-$n$ Threshold `BLS12-381` Federated Cashu—several cryptographic and wire-level subtleties surfaced that are directly relevant to standardizing `BLS12-381` keysets in `cashubtc/nuts`:

---

## 1. Group Selection: Why `min-sig` ($\mathbb{G}_1$ Signatures, $\mathbb{G}_2$ PubKeys) Wins for eCash

`BLS12-381` supports two pairing orientations:
- **`min-pk`:** 48-byte $\mathbb{G}_1$ pubkeys, 96-byte $\mathbb{G}_2$ signatures (`B_` and `C`).
- **`min-sig` (Used by Cowrie):** 96-byte $\mathbb{G}_2$ pubkeys, **48-byte $\mathbb{G}_1$ blinded messages (`B_`) and signatures (`C`)**.

**Recommendation for `NUT-BLS`:** Standardize **`min-sig`**.
Wallets fetch `/v1/keys` once and cache the keyset indefinitely, whereas every QR code, Nostr DM, and `NUT-24` `X-Cashu` HTTP header carries multiple `C` signatures. Furthermore, `NUT-12` (`DLEQ`) becomes **completely unnecessary** under `BLS12-381`:
- Legacy `secp256k1` `BDHKE` proof with `NUT-12` `DLEQ`: `33B (C) + 64B (e, s) = 97 bytes` of cryptographic material per note.
- `BLS12-381` `min-sig` proof with **full public offline pairing verification**: **`48 bytes` total** (**>50% smaller** than `BDHKE + DLEQ`!).

---

## 2. Why Total-Order Pre-Signing ("The Consensus Box") Is Mandatory Even at `4-of-5`

Byzantine quorum intersection at $t = 4, n = 5$ guarantees $|Q_A \cap Q_B| \ge 4 + 4 - 5 = 3$, meaning at least 2 honest signers overlap—so an attacker can never obtain *two* valid 4-of-5 signature sets for conflicting swaps of the same input note $Y$.

However, **consensusless signing still fails via split-state note bricking**:
If two racing devices (or an attacker who observed a bearer token in transit) send `Swap(Y -> B'_1)` to Guardians `{0, 1}` and `Swap(Y -> B'_2)` to Guardians `{2, 3, 4}`, neither branch reaches $t = 4$ shares, permanently locking $Y$ across all 5 honest databases without issuing replacement notes.

Cowrie validates Calle's **Consensus Box** pattern:
1. All `/v1/swap` and `/v1/melt` proposals pass through a total-order state machine *before* any guardian signs (verified by Cowrie's 50-way concurrent swap race test: 1 winner, 49 `11001` `ERR_TOKEN_ALREADY_SPENT` rejections, 0 bricked notes).
2. Every accepted batch records an immutable `BlindSigningTicket` indexed by `B_ -> (ticket_id, out_idx)`, making `NUT-09` (`POST /v1/restore`) completely stateless and crash-safe.

---

## 3. Algebraically Independent Per-Denomination DKG Scalars

Unlike single-key IBE systems (where a server can namespace messages via `H(prefix || m)` because it sees `m` in plaintext), a blind signer receives an opaque uniformly random curve point $B' = r \cdot H(x) \in \mathbb{G}_1$.
- Public linear scalar tweaks ($msk_d = t_d \cdot msk$ or $msk_d = msk + t_d$) are **catastrophically broken** for blind BLS: anyone holding a 1-sat signature $t_1 \cdot msk \cdot H(x)$ can multiply by $t_{1024} \cdot t_1^{-1} \bmod q$ to forge a 1,024-sat signature.
- Every denomination $2^s$ **must** use an algebraically independent secret polynomial in DKG. Cowrie's `DkgParticipant` batches all 32 power-of-2 polynomials into a single 2-round Feldman/Pedersen ceremony (`1.0 KB` of secret scalars per guardian).

---

## 4. Mandatory Fiat-Shamir Weights in Aggregated Batch Verification

`BLS12-381` enables an API server (`NUT-24` `X-Cashu`) or mint (`/v1/melt`) to batch-verify $N$ notes across $K$ active denominations in **$1 + K$ pairings** instead of $2N$ pairings:
$$e\left(\sum_{j=1}^N z_j C_j,\ G_2\right) \stackrel{?}{=} \prod_{s \in \text{slots}} e\left(\sum_{j \in s} z_j H_{\text{DST}}(x_j),\ PK_s\right)$$

**Security subtlety:** Unweighted aggregation ($z_j = 1$) allows an attacker holding two valid notes $(x_1, C_1), (x_2, C_2)$ to submit **individually invalid** proofs $(x_1, C_1 + \Delta)$ and $(x_2, C_2 - \Delta)$ that pass batch verification. Deriving non-zero 128-bit Fiat-Shamir weights $z_j$ from a hash of the full batch transcript (`tbs.rs::verify_batch_notes`) closes this while preserving the $1 + K$ pairing speedup.

---

## 5. `NUT-07` `Ys` Under `BLS12-381`

In `secp256k1` Cashu, `Y = hash_to_curve(secret)` is a 33-byte compressed `secp256k1` point. For `BLS12-381` `min-sig` keysets (e.g. `NUT-02` version prefix `0x02`), `Y = H_dst(secret)` is the **48-byte compressed $\mathbb{G}_1$ point** (`96` hex chars in `/v1/checkstate`). Indexing spent nullifiers by fixed 48-byte `Y` both preserves `NUT-07` unspent-note privacy and prevents unbounded storage DoS from oversized `NUT-10` JSON secrets.
