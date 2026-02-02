# Disclosure Bundle Size Benchmark (Figure 6.2)

Measures the serialized bundle size as a function of revealed fields K, for
invoices of total size N ∈ {5, 10}.

## Environment

| Item            | Value                                    |
|-----------------|------------------------------------------|
| Hardware        | *(fill in: CPU model, RAM, OS)*          |
| Node.js         | v20.20.2 (pinned via Volta)              |
| `@noble/hashes` | 1.3.3                                    |
| `@noble/curves` | 1.2.0 (Schnorr sign/verify)             |

## Encoding

**Compact binary (TLV)**. This is the encoding measured in the thesis.

Fixed header (290 bytes):
`version(1) + txid(32) + merkle_root(32) + merchant_pubkey(32) + merchant_sig(64) + payer_pubkey(32) + intent_sig(64) + intent_hash(32) + K(1)`

Per revealed field:
`name_len(1) + name + value_len(2) + value + nonce(16) + proof_depth(1) + dirs_bitfield(1) + siblings(depth×32)`

If you need JSON-encoded numbers instead (e.g., for a REST API implementation),
expect ~2.5× the binary sizes due to hex encoding + structural overhead.

## Field value size distribution

| Field           | Size (bytes) |
|-----------------|--------------|
| amount          | 8            |
| currency        | 3            |
| timestamp       | 8            |
| merchant_did    | ~40          |
| description     | ~64          |
| recipient_hash  | 32           |
| evidence_tier   | 8            |
| expiry          | 8            |
| payment_hash    | 32           |
| memo            | ~24          |

Mean field value size: ~23 bytes. The per-field slope is sensitive to this distribution.

## Reproduce

```bash
npm install
npm run bench
```

## Output

Results saved to `results/run-<timestamp>/`:
- `sizes.csv` — per-trial sizes (900 rows)
- `summary.csv` — mean/min/max per (N,K) combination
- `fit.json` — linear fit parameters and encoding label
- `stdout.txt` — summary + pgfplots snippet
