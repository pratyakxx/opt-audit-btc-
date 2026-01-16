# Nonce Brute-Force Benchmark (Table 6.2)

Measures how long a brute-force attacker needs to recover the low-entropy
`evidence_tier` field (3 possible values) from its on-chain leaf hash, as a
function of blinding nonce size.

## Environment

| Item           | Value                                    |
|----------------|------------------------------------------|
| Hardware       | *(fill in: CPU model, RAM, OS)*          |
| Node.js        | v20.20.2 (pinned via Volta)              |
| `@noble/hashes`| 1.3.3 (reference tagged-hash only)       |
| OpenSSL/LibreSSL | `openssl version` output on this machine |
| Hot-loop crypto | Node.js built-in `crypto` (OpenSSL-backed) |

## Reproduce

```bash
npm install
npm run bench                        # 60-second 4-byte sample (default)
npm run bench -- --budget-seconds=10 # shorter budget
npm run bench:exhaustive             # full 4-byte search (~2.5 hr on this machine)
```

## What is measured

- **M1**: Node `crypto.createHash('sha256')` throughput on protocol-shaped inputs (1M hashes, 3 runs, median)
- **M2**: LibreSSL/OpenSSL `speed sha256` primitive throughput for 64-byte blocks (if available)
- **M3**: 0-byte nonce — exhaustive 3-candidate search (100K repetitions)
- **M4**: 4-byte nonce — time-bounded brute-force sample, projected to full search space
- **M5**: 8-byte and 16-byte nonces — analytical projection from measured throughput

## Leaf hash shape

```
leaf = tagged_hash("SBI/leaf", field_name || 0x00 || field_value || 0x00 || nonce)
```

Where `tagged_hash(tag, data) = SHA256(SHA256(tag) || SHA256(tag) || data)` per BIP-340.

## Output

Results are saved to `results/run-<timestamp>/`:
- `throughput.csv` — per-run throughput measurements
- `0byte.csv` — mean search time
- `4byte-sample.csv` — sample run stats and projection
- `summary.json` — all results machine-readable
- `stdout.txt` — human-readable summary + LaTeX snippet
