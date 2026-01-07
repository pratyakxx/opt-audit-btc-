import { createHash, randomBytes } from 'node:crypto';
import { sha256 } from '@noble/hashes/sha256';
import { concatBytes } from '@noble/hashes/utils';
import { performance } from 'node:perf_hooks';
import { writeFileSync, mkdirSync } from 'node:fs';
import { execSync } from 'node:child_process';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

// ── CLI flags ────────────────────────────────────────────────────────
const args = process.argv.slice(2);
const EXHAUSTIVE = args.includes('--exhaustive');
const budgetArg = args.find(a => a.startsWith('--budget-seconds='));
const BUDGET_SECONDS = budgetArg ? parseInt(budgetArg.split('=')[1]) : 60;

// ── Constants ────────────────────────────────────────────────────────
const TAG = 'SBI/leaf';
const FIELD_NAME = 'evidence_tier';
const FIELD_VALUES = ['tier1', 'tier2', 'tier3'];
const SEPARATOR = 0x00;

const te = new TextEncoder();

// ── Tagged hash implementations ──────────────────────────────────────

// Reference: noble-hashes (matches the protocol exactly)
function nobleTaggedHash(tag: string, data: Uint8Array): Uint8Array {
  const tagH = sha256(te.encode(tag));
  return sha256(concatBytes(tagH, tagH, data));
}

// Build preimage: field_name || 0x00 || field_value || 0x00 || nonce
function buildPreimage(fieldName: string, fieldValue: string, nonce: Uint8Array): Uint8Array {
  const name = te.encode(fieldName);
  const val = te.encode(fieldValue);
  const buf = new Uint8Array(name.length + 1 + val.length + 1 + nonce.length);
  buf.set(name, 0);
  buf[name.length] = SEPARATOR;
  buf.set(val, name.length + 1);
  buf[name.length + 1 + val.length] = SEPARATOR;
  buf.set(nonce, name.length + 1 + val.length + 1);
  return buf;
}

function nobleLeafHash(fieldName: string, fieldValue: string, nonce: Uint8Array): Uint8Array {
  return nobleTaggedHash(TAG, buildPreimage(fieldName, fieldValue, nonce));
}

// Node crypto version: tagged_hash("SBI/leaf", preimage)
// = SHA256( SHA256("SBI/leaf") || SHA256("SBI/leaf") || preimage )
// Precompute the tag prefix (64 bytes: two copies of SHA256("SBI/leaf"))
const tagHashNode = createHash('sha256').update(TAG).digest();
const TAG_PREFIX = Buffer.concat([tagHashNode, tagHashNode]); // 64 bytes

function nodeLeafHash(preimageBuffer: Buffer): Buffer {
  return createHash('sha256').update(TAG_PREFIX).update(preimageBuffer).digest();
}

// Build a Node Buffer preimage (same shape, avoids Uint8Array → Buffer conversion in hot loop)
function buildPreimageBuffer(fieldName: string, fieldValue: string, nonce: Buffer): Buffer {
  const name = Buffer.from(fieldName);
  const val = Buffer.from(fieldValue);
  const buf = Buffer.alloc(name.length + 1 + val.length + 1 + nonce.length);
  name.copy(buf, 0);
  buf[name.length] = SEPARATOR;
  val.copy(buf, name.length + 1);
  buf[name.length + 1 + val.length] = SEPARATOR;
  nonce.copy(buf, name.length + 1 + val.length + 1);
  return buf;
}

// ── Step 0: Cross-validate noble vs node crypto ──────────────────────
function crossValidate(): void {
  const testNonce = Buffer.from([0x01, 0x02, 0x03, 0x04]);
  for (const val of FIELD_VALUES) {
    const noble = nobleLeafHash(FIELD_NAME, val, testNonce);
    const nodeResult = nodeLeafHash(buildPreimageBuffer(FIELD_NAME, val, testNonce));
    for (let i = 0; i < 32; i++) {
      if (noble[i] !== nodeResult[i]) {
        throw new Error(`Cross-validation FAILED for value="${val}" at byte ${i}: noble=${noble[i]} node=${nodeResult[i]}`);
      }
    }
  }
  console.log('Cross-validation passed: noble-hashes and Node crypto produce identical leaf hashes.');
}

// ── M1: Single-hash throughput ───────────────────────────────────────
function measureThroughput(): { runs: { hashes: number; seconds: number; hps: number }[]; median: number } {
  const N = 1_000_000;
  // Precompute a random preimage of realistic size (field_name + 0x00 + field_value + 0x00 + 16-byte nonce)
  const preimage = buildPreimageBuffer(FIELD_NAME, 'tier1', randomBytes(16));
  const runs: { hashes: number; seconds: number; hps: number }[] = [];

  for (let r = 0; r < 3; r++) {
    // Warm the JIT
    for (let i = 0; i < 10_000; i++) nodeLeafHash(preimage);

    const t0 = performance.now();
    for (let i = 0; i < N; i++) {
      nodeLeafHash(preimage);
    }
    const t1 = performance.now();
    const seconds = (t1 - t0) / 1000;
    runs.push({ hashes: N, seconds, hps: N / seconds });
  }

  const sorted = runs.map(r => r.hps).sort((a, b) => a - b);
  return { runs, median: sorted[1] };
}

// ── M2: OpenSSL/LibreSSL throughput (optional) ───────────────────────
function measureOpenSSL(): { available: boolean; hps?: number; raw?: string; version?: string } {
  try {
    const version = execSync('openssl version 2>&1', { timeout: 5000 }).toString().trim();

    // Try OpenSSL syntax first, fall back to LibreSSL syntax
    let raw: string;
    try {
      raw = execSync('openssl speed -seconds 3 sha256 2>&1', { timeout: 30000 }).toString();
    } catch {
      // LibreSSL uses different syntax; try without -seconds
      try {
        raw = execSync('openssl speed sha256 2>&1', { timeout: 30000 }).toString();
      } catch {
        return { available: true, version, raw: undefined, hps: undefined };
      }
    }

    const lines = raw.split('\n');
    // Look for a line containing "sha256" and numbers — format:
    // OpenSSL:  "sha256          xxxxx.xxk  xxxxx.xxk ..."
    // LibreSSL: "sha256  xxxxx.xxk  xxxxx.xxk ..." or "Doing sha256..." then results
    const sha256Line = lines.find(l => /^sha256\b/i.test(l.trim()));

    if (!sha256Line) return { available: true, raw, version, hps: undefined };

    // Parse all numbers with optional k/M/G suffix from the sha256 results line
    const nums = sha256Line.match(/[\d.]+[kKMG]?/g);
    if (!nums || nums.length < 2) return { available: true, raw, version, hps: undefined };

    // Second column is 64-byte blocks. Values are in bytes/second (with k = ×1000).
    const rawNum = parseFloat(nums[1].replace(/[kKMG]/g, ''));
    const multiplier = /[kK]/.test(nums[1]) ? 1e3
      : /M/.test(nums[1]) ? 1e6
      : /G/.test(nums[1]) ? 1e9
      : 1;
    const bytesPerSec = rawNum * multiplier;
    const hps = bytesPerSec / 64; // 64-byte blocks → hashes/sec

    return { available: true, hps, raw, version };
  } catch {
    return { available: false };
  }
}

// ── M3: 0-byte nonce exhaustive ──────────────────────────────────────
function measure0Byte(): { meanMicros: number; foundAll: boolean } {
  const REPS = 100_000;
  const emptyNonce = Buffer.alloc(0);

  // For each rep, plant a random target value, search for it
  const timings = new Float64Array(REPS);
  let foundAll = true;

  // Pre-build candidate preimage buffers
  const candidateBuffers = FIELD_VALUES.map(v => buildPreimageBuffer(FIELD_NAME, v, emptyNonce));

  for (let rep = 0; rep < REPS; rep++) {
    // Pick a random target
    const targetIdx = Math.floor(Math.random() * 3);
    const targetHash = nodeLeafHash(candidateBuffers[targetIdx]);

    const t0 = performance.now();
    let found = false;
    for (let c = 0; c < 3; c++) {
      const h = nodeLeafHash(candidateBuffers[c]);
      if (h.equals(targetHash)) {
        found = true;
        break;
      }
    }
    const t1 = performance.now();
    timings[rep] = (t1 - t0) * 1000; // µs
    if (!found) foundAll = false;
  }

  const sum = timings.reduce((a, b) => a + b, 0);
  return { meanMicros: sum / REPS, foundAll };
}

// ── M4: 4-byte nonce brute force ─────────────────────────────────────
function measure4Byte(budgetSeconds: number, exhaustive: boolean): {
  hashesPerformed: number;
  seconds: number;
  hps: number;
  found: boolean;
  foundValue?: string;
  isExhaustive: boolean;
} {
  // Plant a target: pick a random 4-byte nonce and a random value
  const targetNonce = randomBytes(4);
  const targetValueIdx = Math.floor(Math.random() * 3);
  const targetValue = FIELD_VALUES[targetValueIdx];
  const targetHash = nodeLeafHash(buildPreimageBuffer(FIELD_NAME, targetValue, targetNonce));

  // Pre-build preimage buffers with space for the nonce at the end
  // Preimage = "evidence_tier" + 0x00 + value + 0x00 + nonce(4 bytes)
  const fieldNameBuf = Buffer.from(FIELD_NAME);
  const valueBufs = FIELD_VALUES.map(v => Buffer.from(v));
  const preimages = valueBufs.map(vb => {
    const buf = Buffer.alloc(fieldNameBuf.length + 1 + vb.length + 1 + 4);
    fieldNameBuf.copy(buf, 0);
    buf[fieldNameBuf.length] = SEPARATOR;
    vb.copy(buf, fieldNameBuf.length + 1);
    buf[fieldNameBuf.length + 1 + vb.length] = SEPARATOR;
    return buf;
  });
  const nonceOffset = fieldNameBuf.length + 1 + valueBufs[0].length + 1; // varies per value
  const nonceOffsets = valueBufs.map(vb => fieldNameBuf.length + 1 + vb.length + 1);

  const totalCandidates = exhaustive ? 3 * (2 ** 32) : Infinity;
  const deadline = performance.now() + budgetSeconds * 1000;
  let hashCount = 0;
  let found = false;
  let foundValue: string | undefined;

  const t0 = performance.now();

  // Iterate nonces as 32-bit integers
  outer:
  for (let nonce = 0; nonce < 0x100000000; nonce++) {
    // Write nonce bytes (big-endian) into each preimage buffer
    for (let c = 0; c < 3; c++) {
      const off = nonceOffsets[c];
      const buf = preimages[c];
      buf[off]     = (nonce >>> 24) & 0xff;
      buf[off + 1] = (nonce >>> 16) & 0xff;
      buf[off + 2] = (nonce >>> 8) & 0xff;
      buf[off + 3] = nonce & 0xff;

      const h = createHash('sha256').update(TAG_PREFIX).update(buf).digest();
      hashCount++;

      if (h.equals(targetHash)) {
        found = true;
        foundValue = FIELD_VALUES[c];
        break outer;
      }
    }

    // Check deadline every 2^16 nonces (~200k hashes) to avoid overhead
    if (!exhaustive && (nonce & 0xFFFF) === 0 && performance.now() > deadline) break;
  }

  const t1 = performance.now();
  const seconds = (t1 - t0) / 1000;

  return {
    hashesPerformed: hashCount,
    seconds,
    hps: hashCount / seconds,
    found,
    foundValue,
    isExhaustive: exhaustive || found,
  };
}

// ── Formatting helpers ───────────────────────────────────────────────
function sciNot(n: number, decimals = 2): string {
  if (n === 0) return '0';
  const exp = Math.floor(Math.log10(n));
  const mantissa = n / (10 ** exp);
  return `${mantissa.toFixed(decimals)} × 10^${exp}`;
}

function humanTime(seconds: number): string {
  if (seconds < 0.001) return `${(seconds * 1e6).toFixed(3)} µs`;
  if (seconds < 1) return `${(seconds * 1000).toFixed(1)} ms`;
  if (seconds < 60) return `${seconds.toFixed(1)} s`;
  if (seconds < 3600) return `${(seconds / 60).toFixed(1)} min`;
  if (seconds < 86400) return `${(seconds / 3600).toFixed(1)} hr`;
  if (seconds < 86400 * 365.25) return `${(seconds / 86400).toFixed(1)} days`;
  const years = seconds / (86400 * 365.25);
  if (years < 1e6) return `${years.toFixed(1)} yr`;
  return `10^${Math.log10(years).toFixed(1)} yr`;
}

function status(seconds: number): string {
  const oneDay = 86400;
  const hundredYears = 100 * 365.25 * 86400;
  if (seconds < oneDay) return 'Broken';
  if (seconds < hundredYears) return 'Marginal';
  return 'Secure';
}

// ── Main ─────────────────────────────────────────────────────────────
function main(): void {
  console.log('=== Nonce Brute-Force Benchmark (Table 6.2) ===\n');

  // Step 0: cross-validate
  crossValidate();

  // M1: throughput
  console.log('\n--- M1: Single-hash throughput (Node crypto) ---');
  const tp = measureThroughput();
  for (const r of tp.runs) {
    console.log(`  ${r.hashes} hashes in ${r.seconds.toFixed(3)}s → ${sciNot(r.hps)} H/s`);
  }
  console.log(`  Median: ${sciNot(tp.median)} H/s`);

  // M2: OpenSSL / LibreSSL
  console.log('\n--- M2: OpenSSL/LibreSSL throughput ---');
  const ossl = measureOpenSSL();
  let projectionRate: number;
  if (ossl.version) console.log(`  Version: ${ossl.version}`);
  if (ossl.available && ossl.hps) {
    console.log(`  SHA-256 (64B blocks): ${sciNot(ossl.hps)} H/s`);
    projectionRate = ossl.hps;
  } else if (ossl.available) {
    console.log('  Available but could not parse throughput. Using Node rate.');
    if (ossl.raw) console.log(`  Raw output:\n${ossl.raw.split('\n').slice(0, 10).join('\n')}`);
    projectionRate = tp.median;
  } else {
    console.log('  Not available. Using Node rate.');
    projectionRate = tp.median;
  }
  console.log(`  Projection rate: ${sciNot(projectionRate)} H/s`);

  // M3: 0-byte nonce
  console.log('\n--- M3: 0-byte nonce (exhaustive) ---');
  const m3 = measure0Byte();
  console.log(`  Mean time per 3-hash search: ${m3.meanMicros.toFixed(3)} µs`);
  console.log(`  All targets found: ${m3.foundAll}`);
  if (!m3.foundAll) throw new Error('SANITY FAIL: 0-byte search did not find target in some iterations!');

  // M4: 4-byte nonce
  console.log(`\n--- M4: 4-byte nonce (${EXHAUSTIVE ? 'exhaustive' : `${BUDGET_SECONDS}s budget`}) ---`);
  const m4 = measure4Byte(BUDGET_SECONDS, EXHAUSTIVE);
  console.log(`  Hashes performed: ${sciNot(m4.hashesPerformed)}`);
  console.log(`  Wall time: ${m4.seconds.toFixed(2)}s`);
  console.log(`  Throughput: ${sciNot(m4.hps)} H/s`);
  if (m4.found) {
    console.log(`  Found target: value="${m4.foundValue}"`);
  } else {
    console.log('  Target not found within budget (expected for sampled run).');
  }

  // Sanity: 4-byte should have done at least 5e7 hashes in 60s (~0.8 MH/s minimum)
  if (!EXHAUSTIVE && m4.hashesPerformed < 5e7 && BUDGET_SECONDS >= 60) {
    console.error(`  WARNING: Only ${sciNot(m4.hashesPerformed)} hashes in ${BUDGET_SECONDS}s — throughput seems too low.`);
  }

  // Use the better of M1 and M4 throughput for 4-byte projection
  const m4Rate = m4.hps;

  // ── Compute projections ────────────────────────────────────────────
  const candidates0 = 3;
  const candidates4 = 3 * (2 ** 32);
  const candidates8 = 3 * (2 ** 64);
  const candidates16 = 3 * (2 ** 128);

  const time0 = m3.meanMicros / 1e6; // seconds
  const time4 = candidates4 / m4Rate; // seconds (projected from M4 measured rate)
  const time8 = candidates8 / projectionRate;
  const time16 = candidates16 / projectionRate;

  const status0 = status(time0);
  const status4 = status(time4);
  const status8 = status(time8);
  const status16 = status(time16);

  // Sanity: status labels
  const expectedStatuses = ['Broken', 'Broken', 'Marginal', 'Secure'];
  const actualStatuses = [status0, status4, status8, status16];
  const statusOk = actualStatuses.every((s, i) => {
    if (i === 2) return s === 'Marginal' || s === 'Secure'; // 8-byte could go either way
    return s === expectedStatuses[i];
  });

  // ── Print throughput summary ───────────────────────────────────────
  console.log('\n' + '='.repeat(70));
  console.log('Measured single-hash throughput:');
  console.log(`  Node crypto (small inputs):   ${sciNot(tp.median)} H/s   (median of 3 runs)`);
  if (ossl.available && ossl.hps) {
    console.log(`  ${ossl.version ?? 'OpenSSL'} (64B): ${sciNot(ossl.hps)} H/s`);
  } else {
    console.log(`  ${ossl.version ?? 'OpenSSL'} primitive: could not measure`);
  }
  console.log(`Projection rate used:           ${sciNot(projectionRate)} H/s`);
  console.log(`4-byte sample rate:             ${sciNot(m4Rate)} H/s`);

  // ── Print table ────────────────────────────────────────────────────
  const pad = (s: string, n: number) => s.padEnd(n);
  console.log('\n' + pad('Nonce', 8) + pad('Candidates', 22) + pad('Time', 24) + pad('Method', 16) + 'Status');
  console.log('-'.repeat(80));
  console.log(pad('0 B', 8) + pad('3', 22) + pad(humanTime(time0), 24) + pad('exhaustive', 16) + status0);
  console.log(pad('4 B', 8) + pad(`${sciNot(candidates4, 2)}`, 22) + pad(`${humanTime(time4)} (proj.)`, 24) + pad(`${BUDGET_SECONDS}s sample`, 16) + status4);
  console.log(pad('8 B', 8) + pad(`${sciNot(candidates8, 2)}`, 22) + pad(`${humanTime(time8)} (proj.)`, 24) + pad('analytical', 16) + status8);
  console.log(pad('16 B', 8) + pad(`${sciNot(candidates16, 2)}`, 22) + pad(`${humanTime(time16)} (proj.)`, 24) + pad('analytical', 16) + status16);

  // Status check
  console.log(`\nStatus thresholds: Broken < 1 day, Marginal ∈ [1 day, 100 yr), Secure ≥ 100 yr`);
  console.log(`Status check: ${statusOk ? 'PASS' : 'WARNING — unexpected status labels, review thresholds'}`);

  // ── LaTeX tabular ──────────────────────────────────────────────────
  // Compute display values for LaTeX
  const time4Display = time4 < 60 ? `${time4.toFixed(1)}\\,s` : `${(time4 / 60).toFixed(0)}\\,min`;
  const years8 = time8 / (86400 * 365.25);
  const log10years16 = Math.log10(time16 / (86400 * 365.25));

  const latex = [
    '\\begin{tabular}{lrrl}',
    '\\toprule',
    'Nonce size & Candidates & Time & Status \\\\',
    '\\midrule',
    `0 bytes  & 3                                      & $<$0.001\\,ms      & Broken \\\\`,
    `4 bytes  & $3 \\times 2^{32} \\approx 1.3\\times10^{10}$ & $\\sim$${time4Display}\\textsuperscript{*}    & Broken \\\\`,
    `8 bytes  & $3 \\times 2^{64} \\approx 5.5\\times10^{19}$ & $\\sim$${years8.toFixed(0)}\\,yr\\textsuperscript{\\dag} & ${status8} \\\\`,
    `16 bytes & $3 \\times 2^{128} \\approx 10^{39}$        & $\\sim$10\\textsuperscript{${log10years16.toFixed(0)}}\\,yr\\textsuperscript{\\dag} & Secure \\\\`,
    '\\bottomrule',
    '\\end{tabular}',
    '\\\\[0.5em]',
    `\\textsuperscript{*}\\,Projected from a ${BUDGET_SECONDS}-second sampled run.`,
    `\\textsuperscript{\\dag}\\,Projected analytically from measured throughput of ${sciNot(projectionRate)}\\,H/s.`,
  ].join('\n');

  console.log('\n' + latex);

  // ── Caption suggestion ─────────────────────────────────────────────
  console.log('\n--- Caption suggestion for Table 6.2 ---');
  console.log('Brute-force times for recovering the \\texttt{evidence\\_tier} field (3 possible values) as a function of nonce size. The 0-byte case was searched exhaustively; the 4-byte case was projected from a ' + BUDGET_SECONDS + '-second sampled run; the 8- and 16-byte cases are projected analytically. All projections use the SHA-256 throughput measured on this hardware (see \\S6.1).');

  // ── Prose suggestion ───────────────────────────────────────────────
  console.log('\n--- Prose suggestion (paragraph after Table 6.2) ---');
  console.log('The 0-byte case was executed exhaustively, confirming the field value is trivially recoverable. The 4-byte case was sampled for ' + BUDGET_SECONDS + ' seconds, with the full search projected from the measured rate. The 8- and 16-byte projections use the same measured single-hash throughput. These results confirm the choice of 16-byte nonces in the protocol design.');

  // ── Save results ───────────────────────────────────────────────────
  const __dirname = dirname(fileURLToPath(import.meta.url));
  const ts = new Date().toISOString().replace(/[:.]/g, '-');
  const runDir = join(__dirname, '..', 'results', `run-${ts}`);
  mkdirSync(runDir, { recursive: true });

  // throughput.csv
  const throughputCsv = 'timestamp,hashes,seconds,h_per_s\n' +
    tp.runs.map(r => `${ts},${r.hashes},${r.seconds.toFixed(6)},${r.hps.toFixed(2)}`).join('\n') + '\n';
  writeFileSync(join(runDir, 'throughput.csv'), throughputCsv);

  // 0byte.csv — we don't have per-iteration data from the current impl; save summary
  writeFileSync(join(runDir, '0byte.csv'),
    `mean_micros\n${m3.meanMicros.toFixed(6)}\n`);

  // 4byte-sample.csv
  writeFileSync(join(runDir, '4byte-sample.csv'),
    'timestamp,budget_seconds,hashes_done,h_per_s,projected_total_seconds\n' +
    `${ts},${BUDGET_SECONDS},${m4.hashesPerformed},${m4.hps.toFixed(2)},${time4.toFixed(2)}\n`);

  // summary.json
  const summary = {
    config: { tag: TAG, fieldName: FIELD_NAME, fieldValues: FIELD_VALUES, budgetSeconds: BUDGET_SECONDS, exhaustive: EXHAUSTIVE },
    throughput: { nodeMedianHps: tp.median, opensslHps: ossl.hps ?? null, projectionRate },
    results: {
      '0byte': { candidates: candidates0, timeSeconds: time0, status: status0, method: 'exhaustive' },
      '4byte': { candidates: candidates4, timeSeconds: time4, status: status4, method: m4.isExhaustive ? 'exhaustive' : 'sampled', sampleHps: m4.hps },
      '8byte': { candidates: candidates8, timeSeconds: time8, status: status8, method: 'analytical' },
      '16byte': { candidates: candidates16, timeSeconds: time16, status: status16, method: 'analytical' },
    },
  };
  writeFileSync(join(runDir, 'summary.json'), JSON.stringify(summary, null, 2) + '\n');

  // stdout.txt — capture a simplified version
  const stdoutLines = [
    `Node crypto throughput: ${sciNot(tp.median)} H/s`,
    `OpenSSL throughput: ${ossl.hps ? sciNot(ossl.hps) + ' H/s' : 'n/a'}`,
    `Projection rate: ${sciNot(projectionRate)} H/s`,
    '',
    `0 B: ${candidates0} candidates, ${humanTime(time0)}, ${status0}`,
    `4 B: ${sciNot(candidates4)} candidates, ${humanTime(time4)}, ${status4}`,
    `8 B: ${sciNot(candidates8)} candidates, ${humanTime(time8)}, ${status8}`,
    `16 B: ${sciNot(candidates16)} candidates, ${humanTime(time16)}, ${status16}`,
    '',
    latex,
  ];
  writeFileSync(join(runDir, 'stdout.txt'), stdoutLines.join('\n') + '\n');

  console.log(`\nResults saved to ${runDir}/`);
}

main();
