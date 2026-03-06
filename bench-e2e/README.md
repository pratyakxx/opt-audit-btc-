# End-to-End Protocol Latency Benchmark (Table 6.6)

Benchmarks the seven phases of one full SBI (Signed Bitcoin Invoice) protocol
execution: encoding, Merkle tree construction, key tweak, transaction
construction + signing, intent signing, bundle generation, and auditor
verification.

## Environment

| Item               | Value                                    |
|--------------------|------------------------------------------|
| Hardware           | *(fill in: CPU model, RAM, OS)*          |
| Node.js            | v20.20.2 (pinned via Volta)              |
| `@noble/secp256k1` | 2.0.0 (pure JS, no WASM/native)         |
| `@noble/hashes`    | 1.3.3                                    |
| `@scure/btc-signer`| 1.3.2                                    |
| TypeScript runner   | tsx                                      |

## Reproduce

```bash
npm install
npm run bench        # full: 3 runs x 100 iterations + 50 warm-up each
npm run smoke        # quick: 1 run x 10 iterations + 5 warm-up
```

## Seven Phases Measured

| # | Phase | Description |
|---|-------|-------------|
| P1 | SBI encoding | Canonical byte encoding of 10 invoice fields |
| P2 | Merkle tree construction | 10 blinded leaves + binary tree, BIP-340 tagged hash |
| P3 | Key tweak computation | `d·G`, `H_TapTweak`, `P_internal + t·G`, even-y normalization, `d_tweaked` |
| P4 | Transaction construction + sign | 1-in / 2-out P2TR tx, BIP-341 sighash, Schnorr signature |
| P5 | Intent message + sign | Payer intent binding (txid + disclosure context), Schnorr signature |
| P6 | Bundle generation (K=3) | Select K=3 fields, gather Merkle proofs, merchant sig, intent sig, serialize JSON |
| P7 | Auditor verification (6 steps) | txid lookup, recipient check, K=3 Merkle proofs, key tweak recompute, 2x Schnorr verify |

## Output

Results are saved to `results/run-<timestamp>/`:
- `p1-sbi-encoding.csv` through `p7-auditor-verify.csv` — per-iteration timings (microseconds)
- `totals.csv` — per-iteration total latency
- `stdout.txt` — human-readable summary + LaTeX snippet
