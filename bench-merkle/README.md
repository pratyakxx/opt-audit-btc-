# Merkle Tree Construction Benchmark (Figure 6.1)

Measures SBI Merkle tree construction time as a function of the number of
invoice fields N, producing data for Figure 6.1 of the thesis.

## Environment

| Item           | Value                                    |
|----------------|------------------------------------------|
| Hardware       | *(fill in: CPU model, RAM, OS)*          |
| Node.js        | v20.20.2 (pinned via Volta)              |
| `@noble/hashes`| 1.3.3 (pure JS, no WASM/native)          |
| TypeScript     | tsx                                      |

## Reproduce

```bash
npm install
npm run bench        # full: 3 runs × 10,000 iterations × 9 N values
npm run smoke        # quick: 1 run × 1,000 iterations × N ∈ {2, 10, 50}
```

## What is measured

For each N ∈ {2, 3, 5, 7, 10, 15, 20, 30, 50}:

1. Generate N field name/value pairs + N random 16-byte nonces (not timed)
2. **Timed region**: compute N leaf hashes + build binary Merkle tree bottom-up → root

Leaf hash: `tagged_hash("SBI/leaf", field_name || 0x00 || field_value || 0x00 || nonce)`
Branch hash: `tagged_hash("SBI/branch", left || right)`

Matches the leaf shape from `bench-nonce` exactly.

## Output

Results are saved to `results/run-<timestamp>/`:
- `per_N.csv` — full raw data (270,000 rows: 9 Ns × 3 runs × 10,000 iters)
- `summary.csv` — median-of-three-runs statistics per N
- `fit.json` — linear regression (slope, intercept, R²)
- `stdout.txt` — summary + pgfplots snippet
