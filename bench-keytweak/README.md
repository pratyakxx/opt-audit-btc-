# Key Tweak Overhead Benchmark (Table 6.5)

Benchmarks normal P2TR key derivation vs. SBI-committed (BIP-341 tweaked) key derivation
to measure the overhead of committing a Signed Bitcoin Invoice Merkle root into a Taproot output.

## Environment

| Item              | Value                                 |
|-------------------|---------------------------------------|
| Hardware          | *(fill in: CPU model, RAM, OS)*       |
| Node.js           | v20.20.2 (pinned via Volta)           |
| `@noble/secp256k1`| 2.0.0 (pure JS, no WASM/native)      |
| `@noble/hashes`   | 1.3.3                                 |
| TypeScript runner  | tsx                                   |

## Reproduce

```bash
npm install
npm run bench
```

## What is measured

- **A. Normal P2TR key gen**: `d·G` scalar multiplication + x-only serialization (32 bytes).
- **B. Tweaked key gen (SBI)**: Same as A, plus BIP-340 tagged hash (`H_TapTweak`), second scalar-mult (`t·G`), EC point addition, and even-y normalization.

10,000 timed iterations per operation, preceded by 1,000 warm-up iterations (discarded).
The pair runs 3 times; the median run (by mean) is reported.

## Output

Results are saved to `results/`:
- `normal.csv` / `tweaked.csv` — per-iteration timings in microseconds (one value per line)
- `run-<timestamp>.txt` — human-readable summary + LaTeX snippet
