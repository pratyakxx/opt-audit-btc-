# opt-audit-btc

Benchmarks and tamper-detection experiments for an **MSc thesis** on a Bitcoin payment-audit protocol — *Optimistic Auditing of Bitcoin Payments via Taproot-committed Signed Bitcoin Invoices (SBI)*.

A merchant commits a Signed Bitcoin Invoice into a Taproot output via BIP-341 key tweak. An auditor later verifies K-of-N disclosed invoice fields using Merkle proofs, without revealing the full invoice on-chain.

---

## Repository Structure

| Directory | Description |
|-----------|-------------|
| `bench-nonce/` | Nonce brute-force resistance benchmark (Table 6.2) |
| `bench-merkle/` | Merkle tree construction benchmark |
| `bench-bundle/` | Bundle serialization + partial verifier (steps 3, 5, 6) |
| `bench-keytweak/` | BIP-341 Taproot key-tweak overhead benchmark |
| `bench-e2e/` | Full 7-phase pipeline + 6-step verifier (authoritative, Table 6.6) |
| `bench-tamper/` | Tamper-detection suite — 7 attacks TM1–TM7 (Table 6.1) |

---

## Protocol Overview

### Commit phase (merchant)
1. Encode invoice fields canonically → **SBI**
2. Blind each field with a random nonce, compute `tagged_hash("SBI/Leaf", name ‖ value ‖ nonce)` per leaf
3. Build a binary Merkle tree with `tagged_hash("SBI/Branch", left ‖ right)`
4. Tweak the internal public key: `P_tweaked = P_internal + t·G` where `t = tagged_hash("SBI/Intent", root)`
5. Construct and broadcast a P2TR transaction paying to `P_tweaked`

### Audit phase (auditor)
| Step | Check |
|------|-------|
| 1 | `txid` format valid + confirmed in a block |
| 2 | Recipient script matches expected P2TR output |
| 3 | K Merkle proofs verify against committed root |
| 4 | Key-tweak recomputed from disclosed root matches on-chain key |
| 5 | Merchant BIP-340 Schnorr signature verifies |
| 6 | Intent signature verifies **and** binds to `txid + disclosure indices` |

---

## Tamper-Detection Results (E6)

| Attack | Description | Detected at Step |
|--------|-------------|-----------------|
| TM1 | Wrong `txid` | 1 |
| TM2 | Wrong recipient script | 2 |
| TM3 | Corrupted Merkle proof | 3 |
| TM4 | Signature replay (different txid) | 6 |
| TM5 | Wrong merchant public key | 5 |
| TM6 | Bad key tweak / wrong `internalPub` | 4 |
| TM7 | Field substitution (valid proof for wrong field) | 3 |

All 7 attacks detected. 0 false negatives. Deterministic.

---

## Dependencies

| Package | Version |
|---------|---------|
| Node.js | v20 LTS |
| `@noble/secp256k1` | 2.0.0 |
| `@noble/hashes` | 1.3.3 |
| `@noble/curves` | 1.3.0 |
| `@scure/btc-signer` | 1.3.2 |
| TypeScript runner | `tsx` |

---

## Reproduce

Each benchmark is self-contained. From any `bench-*/` directory:

```bash
npm install
npm run bench
```

Results are written to `results/run-<timestamp>/`.

---

## Thesis

This repository contains the experimental artefacts for an MSc thesis submitted in 2026.
