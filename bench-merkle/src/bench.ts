import { sha256 } from '@noble/hashes/sha256';
import { concatBytes, randomBytes } from '@noble/hashes/utils';
import { performance } from 'node:perf_hooks';
import { writeFileSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

// ── Config ───────────────────────────────────────────────────────────
const SMOKE     = !!process.env.SMOKE;
const ITERS     = SMOKE ? 1_000 : 10_000;
const WARMUP    = SMOKE ? 100 : 1_000;
const RUNS      = SMOKE ? 1 : 3;
const N_VALUES  = SMOKE ? [2, 10, 50] : [2, 3, 5, 7, 10, 15, 20, 30, 50];

const te = new TextEncoder();

// ── Tagged hash (BIP-340 style) ──────────────────────────────────────
// Precompute tag prefixes once (avoids per-call hashing of tag strings)
function makeTagPrefix(tag: string): Uint8Array {
  const tagH = sha256(te.encode(tag));
  return concatBytes(tagH, tagH); // 64 bytes
}

const LEAF_PREFIX   = makeTagPrefix('SBI/leaf');
const BRANCH_PREFIX = makeTagPrefix('SBI/branch');

function taggedHashLeaf(data: Uint8Array): Uint8Array {
  return sha256(concatBytes(LEAF_PREFIX, data));
}

function taggedHashBranch(left: Uint8Array, right: Uint8Array): Uint8Array {
  return sha256(concatBytes(BRANCH_PREFIX, left, right));
}

// ── Leaf construction ────────────────────────────────────────────────
// Matches bench-nonce shape exactly:
//   tagged_hash("SBI/leaf", field_name || 0x00 || field_value || 0x00 || nonce)
function computeLeaf(fieldName: Uint8Array, fieldValue: Uint8Array, nonce: Uint8Array): Uint8Array {
  const preimage = new Uint8Array(fieldName.length + 1 + fieldValue.length + 1 + nonce.length);
  preimage.set(fieldName, 0);
  preimage[fieldName.length] = 0x00;
  preimage.set(fieldValue, fieldName.length + 1);
  preimage[fieldName.length + 1 + fieldValue.length] = 0x00;
  preimage.set(nonce, fieldName.length + 1 + fieldValue.length + 1);
  return taggedHashLeaf(preimage);
}

// ── Merkle tree (bottom-up, duplicate-last for odd counts) ───────────
function buildMerkleTree(leaves: Uint8Array[]): Uint8Array {
  if (leaves.length === 0) throw new Error('empty leaves');
  if (leaves.length === 1) return leaves[0];

  let current = leaves;
  while (current.length > 1) {
    const next: Uint8Array[] = [];
    for (let i = 0; i < current.length; i += 2) {
      const left = current[i];
      const right = i + 1 < current.length ? current[i + 1] : current[i]; // duplicate last
      next.push(taggedHashBranch(left, right));
    }
    current = next;
  }
  return current[0];
}

// ── Field generation ─────────────────────────────────────────────────
// Plausible field names (cycle through these for N > 10)
const FIELD_NAMES = [
  'amount', 'currency', 'merchant_did', 'recipient_addr', 'timestamp',
  'evidence_tier', 'memo', 'expiry', 'network', 'version',
  'invoice_id', 'payment_hash', 'description', 'fallback_addr', 'route_hints',
  'min_final_cltv', 'payment_secret', 'features', 'metadata', 'signature',
].map(n => te.encode(n));

interface FieldInputs {
  names: Uint8Array[];
  values: Uint8Array[];
  nonces: Uint8Array[];
}

function generateFieldInputs(n: number): FieldInputs {
  const names: Uint8Array[] = [];
  const values: Uint8Array[] = [];
  const nonces: Uint8Array[] = [];
  for (let i = 0; i < n; i++) {
    names.push(FIELD_NAMES[i % FIELD_NAMES.length]);
    // Random value 8–64 bytes
    const vlen = 8 + Math.floor(Math.random() * 57);
    values.push(randomBytes(vlen));
    nonces.push(randomBytes(16));
  }
  return { names, values, nonces };
}

// ── The timed function: leaves + tree build ──────────────────────────
function buildTreeFromInputs(inputs: FieldInputs): Uint8Array {
  const n = inputs.names.length;
  const leaves: Uint8Array[] = new Array(n);
  for (let i = 0; i < n; i++) {
    leaves[i] = computeLeaf(inputs.names[i], inputs.values[i], inputs.nonces[i]);
  }
  return buildMerkleTree(leaves);
}

// ── Determinism assertion ────────────────────────────────────────────
function assertDeterminism(): void {
  const inputs = generateFieldInputs(10);
  const root1 = buildTreeFromInputs(inputs);
  const root2 = buildTreeFromInputs(inputs);
  for (let i = 0; i < 32; i++) {
    if (root1[i] !== root2[i]) {
      throw new Error(`Determinism FAILED at byte ${i}: ${root1[i]} !== ${root2[i]}`);
    }
  }
  console.log('Determinism assertion passed: identical inputs produce identical roots.');
}

// ── Stats ────────────────────────────────────────────────────────────
function computeStats(arr: Float64Array): { mean: number; p50: number; p95: number; p99: number } {
  const sorted = Float64Array.from(arr).sort();
  const sum = sorted.reduce((a, b) => a + b, 0);
  return {
    mean: sum / sorted.length,
    p50:  sorted[Math.floor(sorted.length * 0.50)],
    p95:  sorted[Math.floor(sorted.length * 0.95)],
    p99:  sorted[Math.floor(sorted.length * 0.99)],
  };
}

// ── Linear regression ────────────────────────────────────────────────
function linearFit(xs: number[], ys: number[]): { slope: number; intercept: number; r2: number } {
  const n = xs.length;
  let sx = 0, sy = 0, sxx = 0, sxy = 0, syy = 0;
  for (let i = 0; i < n; i++) {
    sx += xs[i]; sy += ys[i];
    sxx += xs[i] * xs[i]; sxy += xs[i] * ys[i]; syy += ys[i] * ys[i];
  }
  const denom = n * sxx - sx * sx;
  const slope = (n * sxy - sx * sy) / denom;
  const intercept = (sy - slope * sx) / n;
  // R²
  const yMean = sy / n;
  let ssTot = 0, ssRes = 0;
  for (let i = 0; i < n; i++) {
    ssTot += (ys[i] - yMean) ** 2;
    ssRes += (ys[i] - (slope * xs[i] + intercept)) ** 2;
  }
  return { slope, intercept, r2: 1 - ssRes / ssTot };
}

// ── Benchmark ────────────────────────────────────────────────────────
function benchmarkN(n: number, iters: number, warmup: number): Float64Array {
  const timings = new Float64Array(iters);

  // Warm-up with fresh inputs
  for (let i = 0; i < warmup; i++) {
    const inputs = generateFieldInputs(n);
    buildTreeFromInputs(inputs);
  }

  // Timed
  for (let i = 0; i < iters; i++) {
    const inputs = generateFieldInputs(n);
    const t0 = performance.now();
    buildTreeFromInputs(inputs);
    const t1 = performance.now();
    timings[i] = (t1 - t0) * 1000; // ms → µs
  }

  return timings;
}

// ── Main ─────────────────────────────────────────────────────────────
function main(): void {
  console.log(`Config: ${ITERS} iters, ${RUNS} runs, ${WARMUP} warm-up, N values: [${N_VALUES.join(', ')}]`);

  assertDeterminism();

  // Collect all raw timings: [nIdx][runIdx] = Float64Array
  const allTimings: Float64Array[][] = N_VALUES.map(() => []);
  // Median-of-runs stats: [nIdx]
  const summaryStats: { mean: number; p50: number; p95: number; p99: number }[] = [];

  for (let ni = 0; ni < N_VALUES.length; ni++) {
    const n = N_VALUES[ni];
    const runStats: { mean: number; p50: number; p95: number; p99: number }[] = [];

    for (let r = 0; r < RUNS; r++) {
      const timings = benchmarkN(n, ITERS, WARMUP);
      allTimings[ni].push(timings);
      runStats.push(computeStats(timings));
    }

    // Median of runs by mean
    const sortedByMean = [...runStats].sort((a, b) => a.mean - b.mean);
    const medianRun = sortedByMean[Math.floor(RUNS / 2)];
    summaryStats.push(medianRun);

    console.log(`N=${String(n).padStart(2)}: mean=${medianRun.mean.toFixed(1)} µs  p50=${medianRun.p50.toFixed(1)}  p95=${medianRun.p95.toFixed(1)}  p99=${medianRun.p99.toFixed(1)}`);
  }

  // ── Monotonicity check ─────────────────────────────────────────────
  for (let i = 1; i < N_VALUES.length; i++) {
    if (summaryStats[i].mean < summaryStats[i - 1].mean * 0.8) {
      console.error(`WARNING: Non-monotone — N=${N_VALUES[i]} mean (${summaryStats[i].mean.toFixed(1)}) < N=${N_VALUES[i-1]} mean (${summaryStats[i-1].mean.toFixed(1)})`);
    }
  }

  // ── Summary table ──────────────────────────────────────────────────
  const fmt = (n: number) => n.toFixed(1);
  const pad = (s: string, w: number) => s.padStart(w);

  console.log('\n' + '='.repeat(60));
  console.log(pad('N', 4) + pad('Mean (µs)', 12) + pad('p50', 10) + pad('p95', 10) + pad('p99', 10));
  console.log('-'.repeat(60));
  for (let i = 0; i < N_VALUES.length; i++) {
    const s = summaryStats[i];
    console.log(
      pad(String(N_VALUES[i]), 4) +
      pad(fmt(s.mean), 12) +
      pad(fmt(s.p50), 10) +
      pad(fmt(s.p95), 10) +
      pad(fmt(s.p99), 10)
    );
  }
  console.log('='.repeat(60));

  // ── Linear fit ─────────────────────────────────────────────────────
  const means = summaryStats.map(s => s.mean);
  const fit = linearFit(N_VALUES, means);
  console.log(`\nLinear fit: y = ${fit.slope.toFixed(3)} · N + ${fit.intercept.toFixed(3)}`);
  console.log(`  Slope:     ${fit.slope.toFixed(3)} µs/field`);
  console.log(`  Intercept: ${fit.intercept.toFixed(3)} µs`);
  console.log(`  R²:        ${fit.r2.toFixed(6)}`);
  if (fit.r2 < 0.95) {
    console.error(`  WARNING: R² = ${fit.r2.toFixed(4)} < 0.95 — the O(N) claim may not hold or noise is too high.`);
  } else {
    console.log('  R² ≥ 0.95: O(N) claim supported.');
  }

  // ── Thesis claim checks ────────────────────────────────────────────
  console.log('\n--- Thesis claim checks ---');

  // Claim 1: all N ≤ 20 complete in under 100 µs (p99)
  const realisticNs = N_VALUES.filter(n => n <= 20);
  const realisticP99s = realisticNs.map((_, i) => {
    const idx = N_VALUES.indexOf(realisticNs[i]);
    return summaryStats[idx].p99;
  });
  const maxP99 = Math.max(...realisticP99s);
  const maxP99N = realisticNs[realisticP99s.indexOf(maxP99)];
  console.log(`  Max p99 for N ≤ 20: ${fmt(maxP99)} µs (at N=${maxP99N})`);
  if (maxP99 < 100) {
    console.log('  ✓ Claim holds: all N ≤ 20 complete in under 100 µs (p99).');
  } else {
    console.log('  ✗ Claim REFUTED: p99 exceeds 100 µs for N ≤ 20.');
    console.log(`  Suggested caption update: replace "under 100 µs" with "under ${Math.ceil(maxP99 / 10) * 10} µs".`);
  }

  // Claim 2: N=10 mean ≈ 45 µs
  const n10Idx = N_VALUES.indexOf(10);
  const n10Mean = summaryStats[n10Idx].mean;
  const rounded5 = Math.round(n10Mean / 5) * 5;
  console.log(`  N=10 mean: ${fmt(n10Mean)} µs (thesis says ~45 µs)`);
  console.log(`  Suggested prose: replace "approximately 45 µs" with "approximately ${rounded5} µs".`);

  // ── pgfplots snippet ───────────────────────────────────────────────
  const meanCoords = N_VALUES.map((n, i) => `(${n}, ${fmt(summaryStats[i].mean)})`).join(' ');
  const p99Coords = N_VALUES.map((n, i) => `(${n}, ${fmt(summaryStats[i].p99)})`).join(' ');
  const ymax = Math.ceil(Math.max(...summaryStats.map(s => s.p99)) / 50) * 50;

  const pgfplot = `\\begin{tikzpicture}
\\begin{axis}[
    xlabel={Number of fields ($N$)},
    ylabel={Construction time ($\\mu$s)},
    xmin=0, xmax=55,
    ymin=0, ymax=${ymax},
    legend pos=north west,
    grid=major,
    width=0.7\\textwidth,
    height=0.4\\textwidth,
]
\\addplot[blue, mark=*, thick] coordinates {
    ${meanCoords}
};
\\addlegendentry{Mean}
\\addplot[red, mark=triangle, dashed, thick] coordinates {
    ${p99Coords}
};
\\addlegendentry{p99}
\\end{axis}
\\end{tikzpicture}`;

  console.log('\n' + pgfplot);

  // ── Caption suggestion ─────────────────────────────────────────────
  console.log('\n--- Suggested caption ---');
  if (maxP99 < 100 && fit.r2 >= 0.95) {
    console.log('Current caption is accurate. No changes needed.');
    console.log(`"Mean and 99th percentile over ${ITERS.toLocaleString()} iterations. The relationship is linear ($R^2 = ${fit.r2.toFixed(3)}$), and all realistic invoice sizes ($N \\leq 20$) complete in under 100\\,$\\mu$s."`);
  } else {
    const bound = Math.ceil(maxP99 / 10) * 10;
    console.log(`"Mean and 99th percentile over ${ITERS.toLocaleString()} iterations. The relationship is linear ($R^2 = ${fit.r2.toFixed(3)}$), and all realistic invoice sizes ($N \\leq 20$) complete in under ${bound}\\,$\\mu$s."`);
  }

  // ── Prose suggestion ───────────────────────────────────────────────
  console.log('\n--- Suggested prose ---');
  console.log(`"For a typical invoice with 10 fields, tree construction completes in approximately ${rounded5}\\,$\\mu$s (mean), well below any perceptible delay."`);

  // ── Save results ───────────────────────────────────────────────────
  const __dirname = dirname(fileURLToPath(import.meta.url));
  const ts = new Date().toISOString().replace(/[:.]/g, '-');
  const runDir = join(__dirname, '..', 'results', `run-${ts}`);
  mkdirSync(runDir, { recursive: true });

  // per_N.csv — full raw data
  const perNLines: string[] = ['N,run,iter,microseconds'];
  for (let ni = 0; ni < N_VALUES.length; ni++) {
    for (let r = 0; r < allTimings[ni].length; r++) {
      const t = allTimings[ni][r];
      for (let i = 0; i < t.length; i++) {
        perNLines.push(`${N_VALUES[ni]},${r},${i},${t[i].toFixed(3)}`);
      }
    }
  }
  writeFileSync(join(runDir, 'per_N.csv'), perNLines.join('\n') + '\n');

  // summary.csv
  const summaryLines = ['N,mean,p50,p95,p99'];
  for (let i = 0; i < N_VALUES.length; i++) {
    const s = summaryStats[i];
    summaryLines.push(`${N_VALUES[i]},${s.mean.toFixed(3)},${s.p50.toFixed(3)},${s.p95.toFixed(3)},${s.p99.toFixed(3)}`);
  }
  writeFileSync(join(runDir, 'summary.csv'), summaryLines.join('\n') + '\n');

  // fit.json
  writeFileSync(join(runDir, 'fit.json'), JSON.stringify({
    slope_us_per_field: fit.slope,
    intercept_us: fit.intercept,
    r_squared: fit.r2,
  }, null, 2) + '\n');

  // stdout.txt
  // Re-capture isn't trivial; write summary
  const stdoutContent = [
    `Config: ${ITERS} iters, ${RUNS} runs, N values: [${N_VALUES.join(', ')}]`,
    '',
    ...N_VALUES.map((n, i) => {
      const s = summaryStats[i];
      return `N=${n}: mean=${fmt(s.mean)} p50=${fmt(s.p50)} p95=${fmt(s.p95)} p99=${fmt(s.p99)}`;
    }),
    '',
    `Linear fit: y = ${fit.slope.toFixed(3)} · N + ${fit.intercept.toFixed(3)}, R² = ${fit.r2.toFixed(6)}`,
    `Max p99 (N ≤ 20): ${fmt(maxP99)} µs`,
    `N=10 mean: ${fmt(n10Mean)} µs → round to ~${rounded5} µs`,
    '',
    pgfplot,
  ];
  writeFileSync(join(runDir, 'stdout.txt'), stdoutContent.join('\n') + '\n');

  console.log(`\nResults saved to ${runDir}/`);
}

main();
