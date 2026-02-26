import { getPublicKey, ProjectivePoint as Point, etc } from '@noble/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { concatBytes } from '@noble/hashes/utils';
import { performance } from 'node:perf_hooks';
import { writeFileSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

// ── Constants ────────────────────────────────────────────────────────
const WARMUP = 1_000;
const ITERS  = 10_000;
const RUNS   = 3;

// ── BIP-340 tagged hash ──────────────────────────────────────────────
// SHA256(SHA256(tag) || SHA256(tag) || data)
const tagHash = sha256(new TextEncoder().encode('TapTweak'));
const TAG_PREFIX = concatBytes(tagHash, tagHash); // precomputed prefix

function taggedHash(data: Uint8Array): Uint8Array {
  return sha256(concatBytes(TAG_PREFIX, data));
}

// ── Helpers ──────────────────────────────────────────────────────────
function randomBytes32(): Uint8Array {
  return etc.randomBytes(32);
}

/** x-only pubkey: compressed (33 bytes) with the 02/03 prefix stripped */
function xOnlyPubkey(sk: Uint8Array): Uint8Array {
  return getPublicKey(sk, true).slice(1); // 32-byte x-only
}

/** Convert 32-byte scalar to bigint (big-endian) */
function bytesToBigInt(b: Uint8Array): bigint {
  let n = 0n;
  for (let i = 0; i < b.length; i++) n = (n << 8n) | BigInt(b[i]);
  return n;
}

// secp256k1 curve order
const N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;

function stats(arr: Float64Array): { mean: number; median: number; p95: number } {
  const sorted = Float64Array.from(arr).sort();
  const sum = sorted.reduce((a, b) => a + b, 0);
  return {
    mean:   sum / sorted.length,
    median: sorted[Math.floor(sorted.length / 2)],
    p95:    sorted[Math.floor(sorted.length * 0.95)],
  };
}

// ── Pre-generate random inputs ───────────────────────────────────────
// Generate all random data up front so randomBytes() cost doesn't pollute timings.
function generateInputs(count: number): { sks: Uint8Array[]; roots: Uint8Array[] } {
  const sks: Uint8Array[] = [];
  const roots: Uint8Array[] = [];
  for (let i = 0; i < count; i++) {
    sks.push(randomBytes32());
    roots.push(randomBytes32());
  }
  return { sks, roots };
}

// ── Benchmark A: Normal P2TR key gen (scalar-mult + x-only) ─────────
function benchNormal(sks: Uint8Array[], timings: Float64Array): void {
  for (let i = 0; i < timings.length; i++) {
    const t0 = performance.now();
    const _pk = xOnlyPubkey(sks[i]);
    const t1 = performance.now();
    timings[i] = (t1 - t0) * 1000; // ms → µs
  }
}

// ── Benchmark B: Tweaked key gen (SBI) ──────────────────────────────
function benchTweaked(sks: Uint8Array[], roots: Uint8Array[], timings: Float64Array): void {
  for (let i = 0; i < timings.length; i++) {
    const t0 = performance.now();

    // 1. Compute P_internal as Point (reuse for both x-only extraction and addition)
    const P_internal = Point.fromPrivateKey(sks[i]);
    const compressedPub = P_internal.toRawBytes(true);
    const xOnly = compressedPub.slice(1); // 32-byte x-only

    // 2. Tagged hash: t = H_TapTweak(P_internal_xonly || merkle_root)
    const tweakBytes = taggedHash(concatBytes(xOnly, roots[i]));
    const t_scalar = bytesToBigInt(tweakBytes) % N;

    // 3. P_output = P_internal + t·G
    const tG = Point.BASE.multiply(t_scalar);
    const P_output = P_internal.add(tG);

    // 4. Even-y normalization → x-only output
    const _outputBytes = P_output.toRawBytes(true);
    // If y is odd (prefix 0x03), the even-y key is the negation's x (same x, just flip prefix)
    // For x-only we just need the 32 x-bytes regardless (x is the same for P and -P)
    // But BIP-341 wants the even-y point, so we record that the parity may need adjusting
    // for signing. For the output key (address), x-only is bytes [1..33] either way.
    const _xOnlyOutput = _outputBytes.slice(1);

    const t1 = performance.now();
    timings[i] = (t1 - t0) * 1000; // ms → µs
  }
}

// ── Sanity check ─────────────────────────────────────────────────────
function sanityCheck(): void {
  const sk = randomBytes32();
  const root = randomBytes32();

  // Normal: just x-only pubkey
  const normalKey = xOnlyPubkey(sk);

  // Tweaked
  const P_internal = Point.fromPrivateKey(sk);
  const compressed = P_internal.toRawBytes(true);
  const xOnly = compressed.slice(1);
  const tweakBytes = taggedHash(concatBytes(xOnly, root));
  const t_scalar = bytesToBigInt(tweakBytes) % N;
  const tG = Point.BASE.multiply(t_scalar);
  const P_output = P_internal.add(tG);
  const tweakedKey = P_output.toRawBytes(true).slice(1);

  // Keys must differ
  let same = true;
  for (let i = 0; i < 32; i++) {
    if (normalKey[i] !== tweakedKey[i]) { same = false; break; }
  }
  if (same) throw new Error('SANITY FAIL: normal and tweaked keys are identical!');
  console.log('Sanity check passed: normal and tweaked keys differ.');
}

// ── Main ─────────────────────────────────────────────────────────────
function main(): void {
  sanityCheck();

  const totalNeeded = WARMUP + ITERS;

  const normalRuns:  { mean: number; median: number; p95: number }[] = [];
  const tweakedRuns: { mean: number; median: number; p95: number }[] = [];

  const allNormalTimings:  Float64Array[] = [];
  const allTweakedTimings: Float64Array[] = [];

  for (let run = 0; run < RUNS; run++) {
    // Generate fresh random inputs for each run
    const { sks, roots } = generateInputs(totalNeeded);

    // --- Normal ---
    // Warm-up
    const warmupNormal = new Float64Array(WARMUP);
    benchNormal(sks.slice(0, WARMUP), warmupNormal);

    // Timed
    const normalTimings = new Float64Array(ITERS);
    benchNormal(sks.slice(WARMUP, WARMUP + ITERS), normalTimings);
    normalRuns.push(stats(normalTimings));
    allNormalTimings.push(normalTimings);

    // --- Tweaked ---
    // Warm-up
    const warmupTweaked = new Float64Array(WARMUP);
    benchTweaked(sks.slice(0, WARMUP), roots.slice(0, WARMUP), warmupTweaked);

    // Timed
    const tweakedTimings = new Float64Array(ITERS);
    benchTweaked(sks.slice(WARMUP, WARMUP + ITERS), roots.slice(WARMUP, WARMUP + ITERS), tweakedTimings);
    tweakedRuns.push(stats(tweakedTimings));
    allTweakedTimings.push(tweakedTimings);

    console.log(`Run ${run + 1}/${RUNS} done.`);
  }

  // Pick the median run (by mean) for each operation
  const sortedNormal  = [...normalRuns].sort((a, b) => a.mean - b.mean);
  const sortedTweaked = [...tweakedRuns].sort((a, b) => a.mean - b.mean);
  const medianIdx = 1; // index 1 of 3 is the median

  const normalMedianRunIdx  = normalRuns.indexOf(sortedNormal[medianIdx]);
  const tweakedMedianRunIdx = tweakedRuns.indexOf(sortedTweaked[medianIdx]);

  const normalResult  = sortedNormal[medianIdx];
  const tweakedResult = sortedTweaked[medianIdx];

  const overheadMean = tweakedResult.mean - normalResult.mean;
  const overheadPct  = (overheadMean / normalResult.mean) * 100;

  // ── Sanity: expected range check ───────────────────────────────────
  if (normalResult.mean > 1000) {
    console.error(`WARNING: Normal mean ${normalResult.mean.toFixed(1)} µs is >1ms — something may be wrong.`);
  }
  if (overheadMean < 0) {
    console.error(`WARNING: Negative overhead (${overheadMean.toFixed(1)} µs) — investigate before reporting.`);
  }
  if (overheadPct > 250) {
    console.error(`WARNING: Overhead ${overheadPct.toFixed(1)}% is >250% — investigate before reporting.`);
  }

  // ── Human-readable summary ─────────────────────────────────────────
  const fmt = (n: number) => n.toFixed(1);
  const summary = [
    `Normal P2TR key gen:    mean=${fmt(normalResult.mean)} µs   median=${fmt(normalResult.median)} µs   p95=${fmt(normalResult.p95)} µs`,
    `Tweaked key gen (SBI):  mean=${fmt(tweakedResult.mean)} µs   median=${fmt(tweakedResult.median)} µs   p95=${fmt(tweakedResult.p95)} µs`,
    `Overhead (mean):        +${fmt(overheadMean)} µs (+${fmt(overheadPct)}%)`,
  ].join('\n');

  console.log('\n' + summary);

  // ── LaTeX tabular ──────────────────────────────────────────────────
  const latex = `
\\begin{tabular}{lcccc}
\\toprule
Operation & Mean & Median & p95 & Overhead \\\\
\\midrule
Normal P2TR key gen     & ${fmt(normalResult.mean)}\\,$\\mu$s & ${fmt(normalResult.median)}\\,$\\mu$s & ${fmt(normalResult.p95)}\\,$\\mu$s & --- \\\\
Tweaked key gen (SBI)   & ${fmt(tweakedResult.mean)}\\,$\\mu$s & ${fmt(tweakedResult.median)}\\,$\\mu$s & ${fmt(tweakedResult.p95)}\\,$\\mu$s & ${fmt(overheadPct)}\\% \\\\
\\bottomrule
\\end{tabular}`.trim();

  console.log('\n' + latex);

  // ── Write CSV files ────────────────────────────────────────────────
  const __dirname = dirname(fileURLToPath(import.meta.url));
  const resultsDir = join(__dirname, '..', 'results');
  mkdirSync(resultsDir, { recursive: true });

  const normalCsv  = Array.from(allNormalTimings[normalMedianRunIdx]).map(v => v.toFixed(3)).join('\n') + '\n';
  const tweakedCsv = Array.from(allTweakedTimings[tweakedMedianRunIdx]).map(v => v.toFixed(3)).join('\n') + '\n';

  writeFileSync(join(resultsDir, 'normal.csv'), normalCsv);
  writeFileSync(join(resultsDir, 'tweaked.csv'), tweakedCsv);

  // ── Write run log ──────────────────────────────────────────────────
  const ts = new Date().toISOString().replace(/[:.]/g, '-');
  const runLog = [summary, '', latex, ''].join('\n');
  writeFileSync(join(resultsDir, `run-${ts}.txt`), runLog);

  console.log(`\nResults saved to ${resultsDir}/`);
}

main();
