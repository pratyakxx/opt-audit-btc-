import { Transaction, p2tr, NETWORK } from '@scure/btc-signer';
import {
  pubSchnorr, signSchnorr, tagSchnorr,
  taprootTweakPrivKey, taprootTweakPubkey,
  randomPrivateKeyBytes,
} from '@scure/btc-signer/utils';
import { schnorr } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { concatBytes } from '@noble/hashes/utils';
import { performance } from 'node:perf_hooks';
import { writeFileSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

// ── Config ───────────────────────────────────────────────────────────
const SMOKE  = !!process.env.SMOKE;
const ITERS  = SMOKE ? 10 : 100;
const RUNS   = SMOKE ? 1 : 3;
const WARMUP = SMOKE ? 5 : 50;
const N_FIELDS = 10;
const K_REVEAL = 3;

const PHASE_NAMES = [
  'SBI encoding',
  'Merkle tree construction',
  'Key tweak computation',
  'Transaction construction + sign',
  'Intent message + sign',
  'Bundle generation (K=3)',
  'Auditor verification (6 steps)',
] as const;
const N_PHASES = PHASE_NAMES.length;

// ── Helpers ──────────────────────────────────────────────────────────
const te = new TextEncoder();

function randomBytes(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

function bytesToHex(b: Uint8Array): string {
  return Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(hex: string): Uint8Array {
  const a = new Uint8Array(hex.length / 2);
  for (let i = 0; i < a.length; i++) a[i] = parseInt(hex.slice(i*2, i*2+2), 16);
  return a;
}

function uint64Bytes(n: bigint): Uint8Array {
  const b = new Uint8Array(8);
  const dv = new DataView(b.buffer);
  dv.setBigUint64(0, n, false); // big-endian
  return b;
}

function taggedHash(tag: string, ...data: Uint8Array[]): Uint8Array {
  const tagH = sha256(te.encode(tag));
  return sha256(concatBytes(tagH, tagH, ...data));
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

// ── Invoice types ────────────────────────────────────────────────────
interface InvoiceField {
  name: string;
  value: Uint8Array;
}

function generateInvoiceFields(): InvoiceField[] {
  return [
    { name: 'amount',         value: uint64Bytes(BigInt(Math.floor(Math.random() * 1e8))) },
    { name: 'currency',       value: te.encode('BTC') },
    { name: 'merchant_did',   value: te.encode('did:key:z6Mk' + bytesToHex(randomBytes(16))) },
    { name: 'recipient_addr', value: randomBytes(20) },
    { name: 'timestamp',      value: uint64Bytes(BigInt(Math.floor(Date.now() / 1000))) },
    { name: 'evidence_tier',  value: te.encode('STANDARD') },
    { name: 'memo',           value: te.encode('Payment for invoice #' + Math.floor(Math.random()*1e6)) },
    { name: 'expiry',         value: uint64Bytes(BigInt(Math.floor(Date.now() / 1000) + 3600)) },
    { name: 'network',        value: te.encode('mainnet') },
    { name: 'version',        value: new Uint8Array([0x01]) },
  ];
}

// ── P1: SBI Encoding ─────────────────────────────────────────────────
function encodeSBI(fields: InvoiceField[]): Uint8Array {
  // Canonical encoding: N(1 byte) || for each field: nameLen(2) || name || valueLen(2) || value
  const parts: Uint8Array[] = [new Uint8Array([fields.length])];
  for (const f of fields) {
    const nameBytes = te.encode(f.name);
    const nl = new Uint8Array(2);
    new DataView(nl.buffer).setUint16(0, nameBytes.length, false);
    const vl = new Uint8Array(2);
    new DataView(vl.buffer).setUint16(0, f.value.length, false);
    parts.push(nl, nameBytes, vl, f.value);
  }
  return concatBytes(...parts);
}

// ── P2: Merkle tree ──────────────────────────────────────────────────
function computeLeaf(fieldName: string, fieldValue: Uint8Array, nonce: Uint8Array): Uint8Array {
  return taggedHash('SBI/Leaf', te.encode(fieldName), fieldValue, nonce);
}

interface MerkleTree {
  root: Uint8Array;
  leaves: Uint8Array[];
  layers: Uint8Array[][];
}

function buildMerkleTree(leaves: Uint8Array[]): MerkleTree {
  const layers: Uint8Array[][] = [leaves.slice()];
  let current = leaves.slice();
  while (current.length > 1) {
    const next: Uint8Array[] = [];
    for (let i = 0; i < current.length; i += 2) {
      const left = current[i];
      const right = i + 1 < current.length ? current[i + 1] : current[i]; // duplicate if odd
      next.push(taggedHash('SBI/Branch', left, right));
    }
    layers.push(next);
    current = next;
  }
  return { root: current[0], leaves, layers };
}

function getMerkleProof(tree: MerkleTree, index: number): Uint8Array[] {
  const proof: Uint8Array[] = [];
  let idx = index;
  for (let layer = 0; layer < tree.layers.length - 1; layer++) {
    const current = tree.layers[layer];
    const isRight = idx % 2 === 1;
    const siblingIdx = isRight ? idx - 1 : (idx + 1 < current.length ? idx + 1 : idx);
    proof.push(concatBytes(new Uint8Array([isRight ? 1 : 0]), current[siblingIdx]));
    idx = Math.floor(idx / 2);
  }
  return proof;
}

function verifyMerkleProof(leaf: Uint8Array, proof: Uint8Array[], root: Uint8Array): boolean {
  let current = leaf;
  for (const step of proof) {
    const isRight = step[0] === 1;
    const sibling = step.slice(1);
    current = isRight
      ? taggedHash('SBI/Branch', sibling, current)
      : taggedHash('SBI/Branch', current, sibling);
  }
  return equalBytes(current, root);
}

// ── P3: Key tweak ────────────────────────────────────────────────────
interface TweakResult {
  internalPub: Uint8Array;   // 32-byte x-only
  outputPub: Uint8Array;     // 32-byte x-only
  tweakedPriv: Uint8Array;   // 32-byte
  merkleRoot: Uint8Array;    // 32-byte
}

function computeKeyTweak(privKey: Uint8Array, merkleRoot: Uint8Array): TweakResult {
  const internalPub = pubSchnorr(privKey);
  const tweakedPriv = taprootTweakPrivKey(privKey, merkleRoot);
  const [outputPub] = taprootTweakPubkey(internalPub, merkleRoot);
  return { internalPub, outputPub, tweakedPriv, merkleRoot };
}

// ── P4: Transaction construction + sign ──────────────────────────────
interface TxResult {
  txid: Uint8Array;
  txHex: string;
  recipientScript: Uint8Array;
}

function buildAndSignTx(
  tweakedPriv: Uint8Array,
  internalPub: Uint8Array,
  outputPub: Uint8Array,
  merkleRoot: Uint8Array,
  recipientPub: Uint8Array,
): TxResult {
  // Build a synthetic 1-in / 2-out P2TR transaction
  const senderPayment = p2tr(outputPub, undefined, NETWORK);
  const recipientPayment = p2tr(recipientPub, undefined, NETWORK);

  const tx = new Transaction();
  // Synthetic input: spend from a fabricated outpoint with known script
  tx.addInput({
    txid: randomBytes(32),
    index: 0,
    witnessUtxo: {
      amount: 100_000n,
      script: senderPayment.script,
    },
    tapInternalKey: internalPub,
    tapMerkleRoot: merkleRoot,
  });

  // Output 1: recipient
  tx.addOutput({ script: recipientPayment.script, amount: 50_000n });
  // Output 2: change back to sender (tweaked key)
  tx.addOutput({ script: senderPayment.script, amount: 49_000n });

  // Sign with the tweaked private key
  tx.sign(tweakedPriv);
  tx.finalize();

  const raw = tx.extract();
  const txid = sha256(sha256(raw));

  return { txid, txHex: bytesToHex(raw), recipientScript: recipientPayment.script };
}

// ── P5: Intent message + sign ────────────────────────────────────────
interface IntentResult {
  message: Uint8Array;
  signature: Uint8Array;
  payerPub: Uint8Array;
}

function signIntent(
  txid: Uint8Array,
  disclosedIndices: number[],
  payerPriv: Uint8Array,
): IntentResult {
  // Intent message: H("SBI/Intent" || txid || sorted disclosed indices)
  const idxBytes = new Uint8Array(disclosedIndices.sort((a,b) => a-b));
  const message = taggedHash('SBI/Intent', txid, idxBytes);
  const payerPub = pubSchnorr(payerPriv);
  const signature = schnorr.sign(message, payerPriv);
  return { message, signature, payerPub };
}

// ── P6: Bundle generation ────────────────────────────────────────────
interface DisclosureBundle {
  txid: Uint8Array;
  recipientScript: Uint8Array;
  disclosedFields: { name: string; value: Uint8Array; nonce: Uint8Array; proof: Uint8Array[] }[];
  merkleRoot: Uint8Array;
  internalPub: Uint8Array;
  outputPub: Uint8Array;
  merchantSignature: Uint8Array;
  merchantPub: Uint8Array;
  intentSignature: Uint8Array;
  intentMessage: Uint8Array;
  payerPub: Uint8Array;
}

function generateBundle(
  fields: InvoiceField[],
  nonces: Uint8Array[],
  tree: MerkleTree,
  tweak: TweakResult,
  txResult: TxResult,
  intent: IntentResult,
  merchantSig: Uint8Array,
  merchantPub: Uint8Array,
  disclosedIndices: number[],
): DisclosureBundle {
  const disclosedFields = disclosedIndices.map(i => ({
    name: fields[i].name,
    value: fields[i].value,
    nonce: nonces[i],
    proof: getMerkleProof(tree, i),
  }));

  return {
    txid: txResult.txid,
    recipientScript: txResult.recipientScript,
    disclosedFields,
    merkleRoot: tweak.merkleRoot,
    internalPub: tweak.internalPub,
    outputPub: tweak.outputPub,
    merchantSignature: merchantSig,
    merchantPub,
    intentSignature: intent.signature,
    intentMessage: intent.message,
    payerPub: intent.payerPub,
  };
}

// ── P7: Auditor verification ─────────────────────────────────────────
// Simulated tx lookup for the auditor
type TxLookup = Map<string, { recipientScript: Uint8Array; outputScript: Uint8Array }>;

function verifyBundle(bundle: DisclosureBundle, txLookup: TxLookup): { ok: boolean; step: number; error?: string } {
  // Step 1: validate txid format and look up the tx
  const txidHex = bytesToHex(bundle.txid);
  if (bundle.txid.length !== 32) return { ok: false, step: 1, error: 'invalid txid length' };
  const txData = txLookup.get(txidHex);
  if (!txData) return { ok: false, step: 1, error: 'txid not found' };

  // Step 2: verify recipient script matches expectation
  if (!equalBytes(bundle.recipientScript, txData.recipientScript))
    return { ok: false, step: 2, error: 'recipient script mismatch' };

  // Step 3: verify each Merkle proof
  for (const df of bundle.disclosedFields) {
    const leaf = computeLeaf(df.name, df.value, df.nonce);
    if (!verifyMerkleProof(leaf, df.proof, bundle.merkleRoot))
      return { ok: false, step: 3, error: `Merkle proof failed for field ${df.name}` };
  }

  // Step 4: recompute key tweak, verify output key
  const [recomputedOutputPub] = taprootTweakPubkey(bundle.internalPub, bundle.merkleRoot);
  if (!equalBytes(recomputedOutputPub, bundle.outputPub))
    return { ok: false, step: 4, error: 'output key mismatch' };
  // Also verify the output script in the tx matches
  const expectedPayment = p2tr(bundle.outputPub, undefined, NETWORK);
  if (!equalBytes(expectedPayment.script, txData.outputScript))
    return { ok: false, step: 4, error: 'output script mismatch' };

  // Step 5: verify merchant signature on the root
  if (!schnorr.verify(bundle.merchantSignature, bundle.merkleRoot, bundle.merchantPub))
    return { ok: false, step: 5, error: 'merchant signature invalid' };

  // Step 6: verify intent signature
  if (!schnorr.verify(bundle.intentSignature, bundle.intentMessage, bundle.payerPub))
    return { ok: false, step: 6, error: 'intent signature invalid' };

  return { ok: true, step: 6 };
}

// ── Stats ────────────────────────────────────────────────────────────
function stats(arr: Float64Array): { mean: number; p95: number } {
  const sorted = Float64Array.from(arr).sort();
  const sum = sorted.reduce((a, b) => a + b, 0);
  return {
    mean: sum / sorted.length,
    p95:  sorted[Math.floor(sorted.length * 0.95)],
  };
}

// ── Main benchmark ───────────────────────────────────────────────────
function runBenchmark(iters: number, warmup: number): { phaseTimings: Float64Array[]; totalTimings: Float64Array } {
  const phaseTimings = Array.from({ length: N_PHASES }, () => new Float64Array(iters));
  const totalTimings = new Float64Array(iters);

  // Merchant key (fixed across iterations for the "merchant" role)
  const merchantPriv = randomPrivateKeyBytes();
  const merchantPub = pubSchnorr(merchantPriv);

  const doIteration = (recording: boolean, iterIdx: number) => {
    const t: number[] = new Array(N_PHASES + 1);

    // Fresh random inputs per iteration
    const fields = generateInvoiceFields();
    const nonces = Array.from({ length: N_FIELDS }, () => randomBytes(16));
    const internalPriv = randomPrivateKeyBytes();
    const payerPriv = randomPrivateKeyBytes();
    const recipientPriv = randomPrivateKeyBytes();
    const recipientPub = pubSchnorr(recipientPriv);
    const disclosedIndices = pickRandomIndices(N_FIELDS, K_REVEAL);

    // ── P1: SBI encoding ──
    t[0] = performance.now();
    const sbiBytes = encodeSBI(fields);
    t[1] = performance.now();

    // ── P2: Merkle tree construction ──
    const leaves = fields.map((f, i) => computeLeaf(f.name, f.value, nonces[i]));
    const tree = buildMerkleTree(leaves);
    t[2] = performance.now();

    // ── P3: Key tweak computation ──
    const tweak = computeKeyTweak(internalPriv, tree.root);
    t[3] = performance.now();

    // ── P4: Transaction construction + sign ──
    const txResult = buildAndSignTx(tweak.tweakedPriv, tweak.internalPub, tweak.outputPub, tweak.merkleRoot, recipientPub);
    t[4] = performance.now();

    // ── P5: Intent message + sign ──
    const intent = signIntent(txResult.txid, disclosedIndices, payerPriv);
    t[5] = performance.now();

    // ── P6: Bundle generation ──
    // Merchant signs the merkle root
    const merchantSig = schnorr.sign(tree.root, merchantPriv);
    const bundle = generateBundle(fields, nonces, tree, tweak, txResult, intent, merchantSig, merchantPub, disclosedIndices);
    // Serialize bundle to JSON (canonical)
    const _bundleJson = JSON.stringify({
      txid: bytesToHex(bundle.txid),
      recipientScript: bytesToHex(bundle.recipientScript),
      disclosedFields: bundle.disclosedFields.map(df => ({
        name: df.name,
        value: bytesToHex(df.value),
        nonce: bytesToHex(df.nonce),
        proof: df.proof.map(p => bytesToHex(p)),
      })),
      merkleRoot: bytesToHex(bundle.merkleRoot),
      internalPub: bytesToHex(bundle.internalPub),
      outputPub: bytesToHex(bundle.outputPub),
      merchantSignature: bytesToHex(bundle.merchantSignature),
      merchantPub: bytesToHex(bundle.merchantPub),
      intentSignature: bytesToHex(bundle.intentSignature),
      intentMessage: bytesToHex(bundle.intentMessage),
      payerPub: bytesToHex(bundle.payerPub),
    });
    t[6] = performance.now();

    // ── P7: Auditor verification ──
    // Build a simulated tx lookup
    const senderPayment = p2tr(tweak.outputPub, undefined, NETWORK);
    const txLookup: TxLookup = new Map();
    txLookup.set(bytesToHex(txResult.txid), {
      recipientScript: txResult.recipientScript,
      outputScript: senderPayment.script,
    });

    const result = verifyBundle(bundle, txLookup);
    t[7] = performance.now();

    if (!result.ok) {
      throw new Error(`Verification REJECTED at step ${result.step}: ${result.error} (iter ${iterIdx})`);
    }

    if (recording) {
      for (let p = 0; p < N_PHASES; p++) {
        phaseTimings[p][iterIdx] = (t[p + 1] - t[p]) * 1000; // ms → µs
      }
      totalTimings[iterIdx] = (t[N_PHASES] - t[0]) * 1000;
    }
  };

  // Warm-up
  for (let i = 0; i < warmup; i++) doIteration(false, 0);

  // Timed
  for (let i = 0; i < iters; i++) doIteration(true, i);

  return { phaseTimings, totalTimings };
}

function pickRandomIndices(n: number, k: number): number[] {
  const indices: number[] = [];
  const pool = Array.from({ length: n }, (_, i) => i);
  for (let i = 0; i < k; i++) {
    const j = Math.floor(Math.random() * pool.length);
    indices.push(pool[j]);
    pool.splice(j, 1);
  }
  return indices.sort((a, b) => a - b);
}

// ── Tampered bundle test ─────────────────────────────────────────────
function tamperTest(): void {
  const fields = generateInvoiceFields();
  const nonces = Array.from({ length: N_FIELDS }, () => randomBytes(16));
  const internalPriv = randomPrivateKeyBytes();
  const payerPriv = randomPrivateKeyBytes();
  const recipientPub = pubSchnorr(randomPrivateKeyBytes());
  const merchantPriv = randomPrivateKeyBytes();
  const merchantPub = pubSchnorr(merchantPriv);
  const disclosedIndices = [0, 3, 7];

  const leaves = fields.map((f, i) => computeLeaf(f.name, f.value, nonces[i]));
  const tree = buildMerkleTree(leaves);
  const tweak = computeKeyTweak(internalPriv, tree.root);
  const txResult = buildAndSignTx(tweak.tweakedPriv, tweak.internalPub, tweak.outputPub, tweak.merkleRoot, recipientPub);
  const intent = signIntent(txResult.txid, disclosedIndices, payerPriv);
  const merchantSig = schnorr.sign(tree.root, merchantPriv);
  const bundle = generateBundle(fields, nonces, tree, tweak, txResult, intent, merchantSig, merchantPub, disclosedIndices);

  // Tamper: flip one bit in the first disclosed field's value
  const tampered = { ...bundle, disclosedFields: bundle.disclosedFields.map((df, i) => {
    if (i === 0) {
      const badValue = Uint8Array.from(df.value);
      badValue[0] ^= 0x01;
      return { ...df, value: badValue };
    }
    return df;
  })};

  const senderPayment = p2tr(tweak.outputPub, undefined, NETWORK);
  const txLookup: TxLookup = new Map();
  txLookup.set(bytesToHex(txResult.txid), {
    recipientScript: txResult.recipientScript,
    outputScript: senderPayment.script,
  });

  const result = verifyBundle(tampered, txLookup);
  if (result.ok) throw new Error('TAMPER TEST FAILED: tampered bundle was accepted!');
  if (result.step !== 3) throw new Error(`TAMPER TEST: expected rejection at step 3, got step ${result.step}`);
  console.log(`Tamper test passed: tampered bundle rejected at step ${result.step} (${result.error}).`);
}

// ── Main ─────────────────────────────────────────────────────────────
function main(): void {
  console.log(`Config: ${ITERS} iterations, ${RUNS} runs, ${WARMUP} warm-up, N=${N_FIELDS}, K=${K_REVEAL}`);

  // Tamper test first (safety net)
  tamperTest();

  type RunStats = { mean: number; p95: number }[];
  const allRunPhaseStats: RunStats[] = [];
  const allRunTotalStats: { mean: number; p95: number }[] = [];
  const allPhaseTimings: Float64Array[][] = [];
  const allTotalTimings: Float64Array[] = [];

  for (let run = 0; run < RUNS; run++) {
    const { phaseTimings, totalTimings } = runBenchmark(ITERS, WARMUP);
    const phaseStats = phaseTimings.map(pt => stats(pt));
    allRunPhaseStats.push(phaseStats);
    allRunTotalStats.push(stats(totalTimings));
    allPhaseTimings.push(phaseTimings);
    allTotalTimings.push(totalTimings);
    console.log(`Run ${run + 1}/${RUNS} done. Total mean: ${stats(totalTimings).mean.toFixed(1)} µs`);
  }

  // Pick median run by total mean
  const sortedRunIndices = allRunTotalStats
    .map((s, i) => ({ s, i }))
    .sort((a, b) => a.s.mean - b.s.mean);
  const medianRunIdx = sortedRunIndices[Math.floor(RUNS / 2)].i;

  const phaseResults = allRunPhaseStats[medianRunIdx];
  const totalResult = allRunTotalStats[medianRunIdx];

  // Compute shares
  const shares = phaseResults.map(p => (p.mean / totalResult.mean) * 100);
  const shareSum = shares.reduce((a, b) => a + b, 0);

  // Sanity: sum-of-shares
  if (Math.abs(shareSum - 100) > 0.1) {
    console.error(`WARNING: Sum of shares = ${shareSum.toFixed(2)}%, expected 100 ± 0.1`);
  }

  // Sanity: total in plausible range
  if (totalResult.mean < 100) {
    console.error(`WARNING: Total mean ${totalResult.mean.toFixed(1)} µs seems too low (< 100 µs).`);
  }
  if (totalResult.mean > 100_000_000) {
    console.error(`WARNING: Total mean ${(totalResult.mean / 1e6).toFixed(1)} s seems too high.`);
  }

  // Sanity: P3 should be << P4
  const p3Mean = phaseResults[2].mean;
  const p4Mean = phaseResults[3].mean;
  if (p3Mean > p4Mean) {
    console.error(`WARNING: P3 (${p3Mean.toFixed(0)} µs) > P4 (${p4Mean.toFixed(0)} µs) — unexpected.`);
  }

  // Sanity: P7 should be substantial (two schnorr verifications + Merkle proofs)
  const p7Mean = phaseResults[6].mean;
  if (p7Mean < p4Mean / 4) {
    console.error(`WARNING: P7 (${p7Mean.toFixed(0)} µs) seems too small relative to P4 (${p4Mean.toFixed(0)} µs).`);
  }

  // ── Human-readable summary ─────────────────────────────────────────
  const fmt = (n: number) => n.toFixed(1);
  const pad = (s: string, n: number) => s.padEnd(n);

  console.log('\n' + '='.repeat(75));
  console.log(pad('Phase', 36) + pad('Mean (µs)', 14) + pad('p95 (µs)', 14) + 'Share');
  console.log('-'.repeat(75));
  for (let p = 0; p < N_PHASES; p++) {
    console.log(
      pad(PHASE_NAMES[p], 36) +
      pad(fmt(phaseResults[p].mean), 14) +
      pad(fmt(phaseResults[p].p95), 14) +
      fmt(shares[p]) + '%'
    );
  }
  console.log('-'.repeat(75));
  console.log(
    pad('Total', 36) +
    pad(fmt(totalResult.mean), 14) +
    pad(fmt(totalResult.p95), 14) +
    '100.0%'
  );
  console.log('='.repeat(75));

  // ── SBI-specific share (P2 + P3 + P6 + P7) ──
  const sbiShare = shares[1] + shares[2] + shares[5] + shares[6];
  console.log(`\nSBI-specific share: ${fmt(sbiShare)}%`);
  console.log(`  (P2 Merkle: ${fmt(shares[1])}% + P3 Key tweak: ${fmt(shares[2])}% + P6 Bundle: ${fmt(shares[5])}% + P7 Verification: ${fmt(shares[6])}%)`);

  // ── LaTeX tabular ──────────────────────────────────────────────────
  const latex = [
    '\\begin{tabular}{lrrr}',
    '\\toprule',
    'Phase & Mean ($\\mu$s) & p95 ($\\mu$s) & Share \\\\',
    '\\midrule',
    `SBI encoding                    & ${fmt(phaseResults[0].mean)}  & ${fmt(phaseResults[0].p95)}  & ${fmt(shares[0])}\\% \\\\`,
    `Merkle tree construction        & ${fmt(phaseResults[1].mean)}  & ${fmt(phaseResults[1].p95)}  & ${fmt(shares[1])}\\% \\\\`,
    `Key tweak computation           & ${fmt(phaseResults[2].mean)}  & ${fmt(phaseResults[2].p95)}  & ${fmt(shares[2])}\\% \\\\`,
    `Transaction construction + sign & ${fmt(phaseResults[3].mean)}  & ${fmt(phaseResults[3].p95)}  & ${fmt(shares[3])}\\% \\\\`,
    `Intent message + sign           & ${fmt(phaseResults[4].mean)}  & ${fmt(phaseResults[4].p95)}  & ${fmt(shares[4])}\\% \\\\`,
    `Bundle generation ($K = 3$)     & ${fmt(phaseResults[5].mean)}  & ${fmt(phaseResults[5].p95)}  & ${fmt(shares[5])}\\% \\\\`,
    `Auditor verification (6 steps)  & ${fmt(phaseResults[6].mean)}  & ${fmt(phaseResults[6].p95)}  & ${fmt(shares[6])}\\% \\\\`,
    '\\midrule',
    `\\textbf{Total}                  & \\textbf{${fmt(totalResult.mean)}} & \\textbf{${fmt(totalResult.p95)}} & \\textbf{100\\%} \\\\`,
    '\\bottomrule',
    '\\end{tabular}',
  ].join('\n');

  console.log('\n' + latex);

  // ── Save results ───────────────────────────────────────────────────
  const __dirname = dirname(fileURLToPath(import.meta.url));
  const ts = new Date().toISOString().replace(/[:.]/g, '-');
  const runDir = join(__dirname, '..', 'results', `run-${ts}`);
  mkdirSync(runDir, { recursive: true });

  const medianPhaseTimings = allPhaseTimings[medianRunIdx];
  const medianTotalTimings = allTotalTimings[medianRunIdx];

  const phaseFileNames = [
    'p1-sbi-encoding',
    'p2-merkle-tree',
    'p3-key-tweak',
    'p4-tx-sign',
    'p5-intent-sign',
    'p6-bundle-gen',
    'p7-auditor-verify',
  ];

  for (let p = 0; p < N_PHASES; p++) {
    const csv = Array.from(medianPhaseTimings[p]).map(v => v.toFixed(3)).join('\n') + '\n';
    writeFileSync(join(runDir, `${phaseFileNames[p]}.csv`), csv);
  }
  writeFileSync(join(runDir, 'totals.csv'),
    Array.from(medianTotalTimings).map(v => v.toFixed(3)).join('\n') + '\n');

  // Capture full output
  const summaryLines: string[] = [];
  summaryLines.push(`Config: ${ITERS} iterations, ${RUNS} runs, ${WARMUP} warm-up, N=${N_FIELDS}, K=${K_REVEAL}`);
  summaryLines.push('');
  for (let p = 0; p < N_PHASES; p++) {
    summaryLines.push(`${PHASE_NAMES[p]}: mean=${fmt(phaseResults[p].mean)} µs, p95=${fmt(phaseResults[p].p95)} µs, share=${fmt(shares[p])}%`);
  }
  summaryLines.push(`Total: mean=${fmt(totalResult.mean)} µs, p95=${fmt(totalResult.p95)} µs`);
  summaryLines.push('');
  summaryLines.push(`SBI-specific share: ${fmt(sbiShare)}%`);
  summaryLines.push('');
  summaryLines.push(latex);
  writeFileSync(join(runDir, 'stdout.txt'), summaryLines.join('\n') + '\n');

  console.log(`\nResults saved to ${runDir}/`);
}

main();
