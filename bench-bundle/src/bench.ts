import { sha256 } from '@noble/hashes/sha256';
import { concatBytes, randomBytes } from '@noble/hashes/utils';
import { schnorr } from '@noble/curves/secp256k1';
import { writeFileSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

// ── Config ───────────────────────────────────────────────────────────
const TRIALS = 100;
const NK_COMBOS: [number, number][] = [
  [5, 1], [5, 2], [5, 3], [5, 5],
  [10, 1], [10, 2], [10, 3], [10, 5], [10, 10],
];

const te = new TextEncoder();

// ── Helpers ──────────────────────────────────────────────────────────
function bytesToHex(b: Uint8Array): string {
  return Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(hex: string): Uint8Array {
  const a = new Uint8Array(hex.length / 2);
  for (let i = 0; i < a.length; i++) a[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return a;
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

// ── Tagged hash (BIP-340 style, matching bench-merkle/bench-nonce) ──
function makeTagPrefix(tag: string): Uint8Array {
  const tagH = sha256(te.encode(tag));
  return concatBytes(tagH, tagH);
}

const LEAF_PREFIX   = makeTagPrefix('SBI/leaf');
const BRANCH_PREFIX = makeTagPrefix('SBI/branch');
const INTENT_PREFIX = makeTagPrefix('SBI/intent');

function taggedHashLeaf(data: Uint8Array): Uint8Array {
  return sha256(concatBytes(LEAF_PREFIX, data));
}
function taggedHashBranch(left: Uint8Array, right: Uint8Array): Uint8Array {
  return sha256(concatBytes(BRANCH_PREFIX, left, right));
}
function taggedHashIntent(data: Uint8Array): Uint8Array {
  return sha256(concatBytes(INTENT_PREFIX, data));
}

// ── Leaf hash (matches bench-nonce shape exactly) ────────────────────
function computeLeaf(fieldName: string, fieldValue: Uint8Array, nonce: Uint8Array): Uint8Array {
  const nameBytes = te.encode(fieldName);
  const preimage = new Uint8Array(nameBytes.length + 1 + fieldValue.length + 1 + nonce.length);
  preimage.set(nameBytes, 0);
  preimage[nameBytes.length] = 0x00;
  preimage.set(fieldValue, nameBytes.length + 1);
  preimage[nameBytes.length + 1 + fieldValue.length] = 0x00;
  preimage.set(nonce, nameBytes.length + 1 + fieldValue.length + 1);
  return taggedHashLeaf(preimage);
}

// ── Merkle tree (matching bench-merkle) ──────────────────────────────
interface MerkleTree {
  root: Uint8Array;
  leaves: Uint8Array[];
  layers: Uint8Array[][];
}

function buildMerkleTree(leaves: Uint8Array[]): MerkleTree {
  if (leaves.length === 0) throw new Error('empty leaves');
  const layers: Uint8Array[][] = [leaves.slice()];
  let current = leaves.slice();
  while (current.length > 1) {
    const next: Uint8Array[] = [];
    for (let i = 0; i < current.length; i += 2) {
      const left = current[i];
      const right = i + 1 < current.length ? current[i + 1] : current[i];
      next.push(taggedHashBranch(left, right));
    }
    layers.push(next);
    current = next;
  }
  return { root: current[0], leaves, layers };
}

function getMerkleProof(tree: MerkleTree, index: number): { siblings: Uint8Array[]; dirs: number[] } {
  const siblings: Uint8Array[] = [];
  const dirs: number[] = [];
  let idx = index;
  for (let layer = 0; layer < tree.layers.length - 1; layer++) {
    const current = tree.layers[layer];
    const isRight = idx % 2 === 1;
    const siblingIdx = isRight ? idx - 1 : (idx + 1 < current.length ? idx + 1 : idx);
    siblings.push(current[siblingIdx]);
    dirs.push(isRight ? 1 : 0);
    idx = Math.floor(idx / 2);
  }
  return { siblings, dirs };
}

function verifyMerkleProof(leaf: Uint8Array, siblings: Uint8Array[], dirs: number[], root: Uint8Array): boolean {
  let current = leaf;
  for (let i = 0; i < siblings.length; i++) {
    current = dirs[i] === 1
      ? taggedHashBranch(siblings[i], current)
      : taggedHashBranch(current, siblings[i]);
  }
  return equalBytes(current, root);
}

// ── Field definitions with realistic sizes ───────────────────────────
interface FieldDef {
  name: string;
  genValue: () => Uint8Array;
  typicalSize: number;
}

const FIELD_DEFS: FieldDef[] = [
  { name: 'amount',         genValue: () => randomBytes(8),   typicalSize: 8 },
  { name: 'currency',       genValue: () => te.encode('USD'), typicalSize: 3 },
  { name: 'timestamp',      genValue: () => randomBytes(8),   typicalSize: 8 },
  { name: 'merchant_did',   genValue: () => te.encode('did:key:z6Mk' + bytesToHex(randomBytes(16))), typicalSize: 40 },
  { name: 'description',    genValue: () => te.encode('Payment for services rendered, inv #' + Math.floor(Math.random() * 1e6)), typicalSize: 64 },
  { name: 'recipient_hash', genValue: () => randomBytes(32),  typicalSize: 32 },
  { name: 'evidence_tier',  genValue: () => te.encode('STANDARD'), typicalSize: 8 },
  { name: 'expiry',         genValue: () => randomBytes(8),   typicalSize: 8 },
  { name: 'payment_hash',   genValue: () => randomBytes(32),  typicalSize: 32 },
  { name: 'memo',           genValue: () => te.encode('Reference: TX-' + Math.floor(Math.random() * 1e8)), typicalSize: 24 },
];

interface Field { name: string; value: Uint8Array; }

function generateFields(n: number): Field[] {
  return Array.from({ length: n }, (_, i) => {
    const def = FIELD_DEFS[i % FIELD_DEFS.length];
    return { name: def.name, value: def.genValue() };
  });
}

// ── Bundle types ─────────────────────────────────────────────────────
interface RevealedField {
  field_name: string;
  field_value: Uint8Array;
  nonce: Uint8Array;              // 16 bytes
  siblings: Uint8Array[];         // each 32 bytes
  dirs: number[];                 // direction bits
}

interface Bundle {
  txid: Uint8Array;               // 32
  merkle_root: Uint8Array;        // 32
  merchant_signature: Uint8Array; // 64
  merchant_pubkey: Uint8Array;    // 32
  intent_signature: Uint8Array;   // 64
  intent_message: Uint8Array;     // 32 (a tagged hash of the full intent)
  payer_pubkey: Uint8Array;       // 32
  revealed_fields: RevealedField[];
}
// Fixed header: 32+32+64+32+64+32+32 = 288 bytes + 2 bytes (version + K count) = 290

// ── Compact binary serialization ─────────────────────────────────────
// Layout:
//   version:            1 byte  (0x01)
//   txid:              32 bytes
//   merkle_root:       32 bytes
//   merchant_pubkey:   32 bytes
//   merchant_signature:64 bytes
//   payer_pubkey:      32 bytes
//   intent_signature:  64 bytes
//   intent_message:    32 bytes  (tagged hash)
//   K:                  1 byte
//   For each revealed field:
//     name_len:         1 byte
//     name:             name_len bytes
//     value_len:        2 bytes (big-endian)
//     value:            value_len bytes
//     nonce:           16 bytes
//     proof_depth:      1 byte
//     dirs_bitfield:    1 byte  (up to 8 levels)
//     siblings:         proof_depth × 32 bytes

function serializeBundleBinary(b: Bundle): Uint8Array {
  // Calculate total size
  let size = 1 + 32 + 32 + 32 + 64 + 32 + 64 + 32 + 1; // header = 290
  for (const rf of b.revealed_fields) {
    const nameBytes = te.encode(rf.field_name);
    size += 1 + nameBytes.length + 2 + rf.field_value.length + 16 + 1 + 1 + rf.siblings.length * 32;
  }

  const buf = new Uint8Array(size);
  const dv = new DataView(buf.buffer);
  let off = 0;

  const write = (data: Uint8Array) => { buf.set(data, off); off += data.length; };
  const writeByte = (v: number) => { buf[off++] = v; };
  const writeU16 = (v: number) => { dv.setUint16(off, v, false); off += 2; };

  writeByte(0x01); // version
  write(b.txid);
  write(b.merkle_root);
  write(b.merchant_pubkey);
  write(b.merchant_signature);
  write(b.payer_pubkey);
  write(b.intent_signature);
  write(b.intent_message);
  writeByte(b.revealed_fields.length);

  for (const rf of b.revealed_fields) {
    const nameBytes = te.encode(rf.field_name);
    writeByte(nameBytes.length);
    write(nameBytes);
    writeU16(rf.field_value.length);
    write(rf.field_value);
    write(rf.nonce);
    writeByte(rf.siblings.length);
    // Pack direction bits into a single byte
    let dirsByte = 0;
    for (let i = 0; i < rf.dirs.length; i++) dirsByte |= (rf.dirs[i] << i);
    writeByte(dirsByte);
    for (const sib of rf.siblings) write(sib);
  }

  if (off !== size) throw new Error(`Serialization bug: wrote ${off}, expected ${size}`);
  return buf;
}

function deserializeBundleBinary(buf: Uint8Array): Bundle {
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  let off = 0;

  const readBytes = (n: number): Uint8Array => { const s = buf.slice(off, off + n); off += n; return s; };
  const readByte = (): number => buf[off++];
  const readU16 = (): number => { const v = dv.getUint16(off, false); off += 2; return v; };

  const version = readByte();
  if (version !== 0x01) throw new Error(`Unknown version ${version}`);

  const txid = readBytes(32);
  const merkle_root = readBytes(32);
  const merchant_pubkey = readBytes(32);
  const merchant_signature = readBytes(64);
  const payer_pubkey = readBytes(32);
  const intent_signature = readBytes(64);
  const intent_message = readBytes(32);
  const k = readByte();

  const revealed_fields: RevealedField[] = [];
  for (let i = 0; i < k; i++) {
    const nameLen = readByte();
    const field_name = new TextDecoder().decode(readBytes(nameLen));
    const valueLen = readU16();
    const field_value = readBytes(valueLen);
    const nonce = readBytes(16);
    const proofDepth = readByte();
    const dirsByte = readByte();
    const dirs: number[] = [];
    for (let d = 0; d < proofDepth; d++) dirs.push((dirsByte >> d) & 1);
    const siblings: Uint8Array[] = [];
    for (let s = 0; s < proofDepth; s++) siblings.push(readBytes(32));
    revealed_fields.push({ field_name, field_value, nonce, siblings, dirs });
  }

  return { txid, merkle_root, merchant_signature, merchant_pubkey, intent_signature, intent_message, payer_pubkey, revealed_fields };
}

// ── Intent message ───────────────────────────────────────────────────
// The intent message stored in the bundle is a 32-byte tagged hash of the full
// intent context (txid, disclosed indices, timestamp). This matches §4's design
// where the auditor can recompute the hash from the bundle's context.
function buildIntentHash(txid: Uint8Array, disclosedIndices: number[]): Uint8Array {
  const timestamp = new Uint8Array(8);
  new DataView(timestamp.buffer).setBigUint64(0, BigInt(Math.floor(Date.now() / 1000)), false);
  const indices = new Uint8Array(disclosedIndices);
  return taggedHashIntent(concatBytes(txid, timestamp, indices));
}

// ── Bundle construction ──────────────────────────────────────────────
function constructBundle(n: number, k: number): { bundle: Bundle; binary: Uint8Array } {
  const fields = generateFields(n);
  const nonces = Array.from({ length: n }, () => randomBytes(16));
  const leaves = fields.map((f, i) => computeLeaf(f.name, f.value, nonces[i]));
  const tree = buildMerkleTree(leaves);

  const merchantPriv = schnorr.utils.randomPrivateKey();
  const merchantPub = schnorr.getPublicKey(merchantPriv);
  const merchantSig = schnorr.sign(tree.root, merchantPriv);

  const payerPriv = schnorr.utils.randomPrivateKey();
  const payerPub = schnorr.getPublicKey(payerPriv);

  const disclosedIndices = Array.from({ length: k }, (_, i) => i);
  const txid = randomBytes(32);
  const intentHash = buildIntentHash(txid, disclosedIndices);
  const intentSig = schnorr.sign(intentHash, payerPriv);

  const revealedFields: RevealedField[] = disclosedIndices.map(idx => {
    const { siblings, dirs } = getMerkleProof(tree, idx);
    return {
      field_name: fields[idx].name,
      field_value: fields[idx].value,
      nonce: nonces[idx],
      siblings,
      dirs,
    };
  });

  const bundle: Bundle = {
    txid,
    merkle_root: tree.root,
    merchant_signature: merchantSig,
    merchant_pubkey: merchantPub,
    intent_signature: intentSig,
    intent_message: intentHash,
    payer_pubkey: payerPub,
    revealed_fields: revealedFields,
  };

  return { bundle, binary: serializeBundleBinary(bundle) };
}

// ── Verification (steps 3, 5, 6) ─────────────────────────────────────
function verifyBundle(b: Bundle): { ok: boolean; step: number; error?: string } {
  for (const rf of b.revealed_fields) {
    const leaf = computeLeaf(rf.field_name, rf.field_value, rf.nonce);
    if (!verifyMerkleProof(leaf, rf.siblings, rf.dirs, b.merkle_root))
      return { ok: false, step: 3, error: `Merkle proof failed for ${rf.field_name}` };
  }
  if (!schnorr.verify(b.merchant_signature, b.merkle_root, b.merchant_pubkey))
    return { ok: false, step: 5, error: 'merchant signature invalid' };
  if (!schnorr.verify(b.intent_signature, b.intent_message, b.payer_pubkey))
    return { ok: false, step: 6, error: 'intent signature invalid' };
  return { ok: true, step: 6 };
}

// ── Assertions ───────────────────────────────────────────────────────
function assertRoundTrip(): void {
  const { bundle, binary } = constructBundle(10, 3);
  const deserialized = deserializeBundleBinary(binary);
  const reserialized = serializeBundleBinary(deserialized);
  if (!equalBytes(binary, reserialized))
    throw new Error('Round-trip FAILED: serialize → deserialize → serialize not byte-equal.');
  console.log('Round-trip assertion passed.');
}

function assertVerification(): void {
  const { bundle } = constructBundle(10, 3);
  const result = verifyBundle(bundle);
  if (!result.ok) throw new Error(`Verification FAILED at step ${result.step}: ${result.error}`);
  console.log('Verification assertion passed: well-formed bundle ACCEPTs.');
}

// ── Linear regression ────────────────────────────────────────────────
function linearFit(xs: number[], ys: number[]): { slope: number; intercept: number; r2: number } {
  const n = xs.length;
  let sx = 0, sy = 0, sxx = 0, sxy = 0;
  for (let i = 0; i < n; i++) { sx += xs[i]; sy += ys[i]; sxx += xs[i] * xs[i]; sxy += xs[i] * ys[i]; }
  const denom = n * sxx - sx * sx;
  const slope = (n * sxy - sx * sy) / denom;
  const intercept = (sy - slope * sx) / n;
  const yMean = sy / n;
  let ssTot = 0, ssRes = 0;
  for (let i = 0; i < n; i++) { ssTot += (ys[i] - yMean) ** 2; ssRes += (ys[i] - (slope * xs[i] + intercept)) ** 2; }
  return { slope, intercept, r2: 1 - ssRes / ssTot };
}

// ── Main ─────────────────────────────────────────────────────────────
function main(): void {
  console.log('Encoding: compact binary (TLV)');
  console.log(`Fixed header: version(1) + txid(32) + root(32) + merch_pub(32) + merch_sig(64) + payer_pub(32) + intent_sig(64) + intent_hash(32) + K(1) = 290 bytes`);
  console.log(`Per-field: name_len(1) + name + value_len(2) + value + nonce(16) + depth(1) + dirs(1) + siblings(depth×32)`);
  console.log(`Field value sizes: ${FIELD_DEFS.map(f => `${f.name}:${f.typicalSize}B`).join(', ')}\n`);

  assertRoundTrip();
  assertVerification();

  // Smoke: single (N=10, K=3) with hex dump
  console.log('\n--- Smoke: N=10, K=3 ---');
  const { bundle: smokeB, binary: smokeBin } = constructBundle(10, 3);
  console.log(`  Bundle size: ${smokeBin.length} bytes`);
  console.log(`  Verification: ${verifyBundle(smokeB).ok ? 'ACCEPT' : 'REJECT'}`);
  console.log(`  Header (first 32 bytes hex): ${bytesToHex(smokeBin.slice(0, 32))}`);

  // Full measurement
  console.log('\n--- Full measurement ---');
  const results: Map<string, { sizes: number[]; mean: number; min: number; max: number }> = new Map();

  for (const [n, k] of NK_COMBOS) {
    const sizes: number[] = [];
    for (let t = 0; t < TRIALS; t++) {
      const { bundle, binary } = constructBundle(n, k);
      const v = verifyBundle(bundle);
      if (!v.ok) throw new Error(`REJECT at (N=${n},K=${k},trial=${t}), step ${v.step}: ${v.error}`);
      sizes.push(binary.length);
    }
    const mean = Math.round(sizes.reduce((a, b) => a + b, 0) / sizes.length);
    const min = Math.min(...sizes);
    const max = Math.max(...sizes);
    results.set(`${n},${k}`, { sizes, mean, min, max });
    console.log(`  N=${String(n).padStart(2)}, K=${String(k).padStart(2)}: mean=${mean}  min=${min}  max=${max}  spread=${max - min}`);
  }

  // ── Summary table ──────────────────────────────────────────────────
  const pad = (s: string, w: number) => s.padStart(w);
  console.log('\n' + '='.repeat(65));
  console.log(pad('N', 4) + pad('K', 6) + pad('Mean', 10) + pad('Min', 8) + pad('Max', 8) + '   Notes');
  console.log('-'.repeat(65));
  for (const [n, k] of NK_COMBOS) {
    const r = results.get(`${n},${k}`)!;
    let note = '';
    if (n === k) note = `full disclosure (N=${n})`;
    if (n === 10 && k === 3) note = 'typical case';
    console.log(pad(String(n), 4) + pad(String(k), 6) + pad(String(r.mean), 10) + pad(String(r.min), 8) + pad(String(r.max), 8) + (note ? '   ' + note : ''));
  }
  console.log('='.repeat(65));

  // Spread check
  let maxSpread = 0;
  for (const [key, r] of results) {
    const spread = r.max - r.min;
    if (spread > maxSpread) maxSpread = spread;
    if (spread > 50) console.error(`WARNING: Large spread at (${key}): ${spread} bytes`);
  }
  console.log(`Max spread across all cells: ${maxSpread} bytes`);

  // ── Linear fits ────────────────────────────────────────────────────
  const n10Ks = [1, 2, 3, 5, 10];
  const n10Means = n10Ks.map(k => results.get(`10,${k}`)!.mean);
  const fitN10 = linearFit(n10Ks, n10Means);

  const n5Ks = [1, 2, 3, 5];
  const n5Means = n5Ks.map(k => results.get(`5,${k}`)!.mean);
  const fitN5 = linearFit(n5Ks, n5Means);

  console.log('\n--- Linear fit: bytes = a·K + b ---');
  console.log(`  N=10: slope=${fitN10.slope.toFixed(1)} bytes/field, intercept=${fitN10.intercept.toFixed(1)} bytes, R²=${fitN10.r2.toFixed(4)}`);
  console.log(`  N=5:  slope=${fitN5.slope.toFixed(1)} bytes/field, intercept=${fitN5.intercept.toFixed(1)} bytes, R²=${fitN5.r2.toFixed(4)}`);

  if (fitN10.slope > fitN5.slope) {
    console.log('  ✓ N=10 slope > N=5 slope (expected: deeper Merkle proofs)');
  } else {
    console.error('  ✗ N=10 slope ≤ N=5 slope — unexpected');
  }

  const interceptDiff = Math.abs(fitN10.intercept - fitN5.intercept);
  console.log(interceptDiff <= 20
    ? `  ✓ Intercepts differ by ${interceptDiff.toFixed(0)} bytes (within 20-byte tolerance)`
    : `  WARNING: Intercepts differ by ${interceptDiff.toFixed(0)} bytes (expected ≤ 20)`);

  // ── Thesis claim checks ────────────────────────────────────────────
  console.log('\n--- Thesis claim checks ---');

  console.log(`  1. Fixed overhead (N=10 intercept): ${fitN10.intercept.toFixed(0)} bytes (thesis says ~292)`);
  if (Math.abs(fitN10.intercept - 292) <= 50) console.log('     ✓ Within 50 bytes of thesis claim.');
  else console.log(`     ✗ Off by ${Math.abs(fitN10.intercept - 292).toFixed(0)} bytes — suggest ~${Math.round(fitN10.intercept / 10) * 10} bytes.`);

  console.log(`  2. Per-field cost (N=10 slope): ${fitN10.slope.toFixed(0)} bytes (thesis says 100–150)`);
  if (fitN10.slope >= 100 && fitN10.slope <= 150) console.log('     ✓ Within claimed range.');
  else {
    const lo = Math.floor(fitN10.slope / 10) * 10;
    console.log(`     ✗ Outside — suggest "~${lo}–${lo + 50} bytes".`);
  }

  const typicalMean = results.get('10,3')!.mean;
  const typicalRound = Math.round(typicalMean / 50) * 50;
  console.log(`  3. Typical (N=10, K=3): ${typicalMean} bytes (thesis says ~700)`);
  console.log(`     Suggest: "approximately ${typicalRound} bytes".`);

  const fullMax = results.get('10,10')!.max;
  const fullMean = results.get('10,10')!.mean;
  console.log(`  4. Full disclosure (N=10, K=10): mean=${fullMean}, max=${fullMax} bytes (thesis says < 1.6 KB)`);
  if (fullMax < 1638) console.log('     ✓ Under 1.6 KB.');
  else console.log(`     ✗ Exceeds — suggest "under ${(Math.ceil(fullMax / 100) * 100 / 1000).toFixed(1)} KB".`);

  // ── pgfplots snippet ───────────────────────────────────────────────
  const n10Coords = [1, 2, 3, 5, 10].map(k => `(${k}, ${results.get(`10,${k}`)!.mean})`).join(' ');
  const n5Coords = [1, 2, 3, 5].map(k => `(${k}, ${results.get(`5,${k}`)!.mean})`).join(' ');
  const ymax = Math.ceil(fullMax / 500) * 500;

  const pgfplot = `\\begin{tikzpicture}
\\begin{axis}[
    ybar,
    xlabel={Revealed fields ($K$)},
    ylabel={Bundle size (bytes)},
    symbolic x coords={1, 2, 3, 5, 10},
    xtick=data,
    ymin=0, ymax=${ymax},
    bar width=8pt,
    legend pos=north west,
    enlarge x limits=0.15,
    width=0.7\\textwidth,
    height=0.4\\textwidth,
]
\\addplot[fill=blue!50] coordinates {
    ${n10Coords}
};
\\addlegendentry{$N = 10$}
\\addplot[fill=green!50] coordinates {
    ${n5Coords}
};
\\addlegendentry{$N = 5$}
\\end{axis}
\\end{tikzpicture}`;

  console.log('\n' + pgfplot);

  // ── Caption / prose suggestions ────────────────────────────────────
  const slopeRoundLo = Math.floor(fitN10.slope / 10) * 10;
  const slopeRoundHi = slopeRoundLo + 20;
  const interceptRound = Math.round(fitN10.intercept / 10) * 10;

  console.log('\n--- Suggested caption ---');
  console.log(`"Disclosure bundle size as a function of revealed fields $K$, for $N = 5$ and $N = 10$ total fields. The fixed overhead (signatures, keys, transaction reference) is approximately ${interceptRound} bytes. Each additional revealed field adds approximately ${slopeRoundLo}--${slopeRoundHi} bytes (value, nonce, and Merkle proof). A typical disclosure ($K = 3$, $N = 10$) produces a bundle of approximately ${typicalRound} bytes. Encoding: compact binary (TLV)."`);

  console.log('\n--- Suggested prose ---');
  console.log(`"The bundle size is dominated by the fixed overhead (${interceptRound} bytes for signatures, keys, and transaction reference) for small $K$, with each additional disclosed field contributing approximately ${Math.round(fitN10.slope)} bytes. A typical disclosure of $K = 3$ fields from a $N = 10$-field invoice produces a bundle of approximately ${typicalRound} bytes, small enough for a QR code. Even a full disclosure of all 10 fields produces a bundle ${fullMax < 1638 ? 'under 1.6' : `of approximately ${(fullMax / 1024).toFixed(1)}`}\\,KB."`);

  // ── Save results ───────────────────────────────────────────────────
  const __dirname = dirname(fileURLToPath(import.meta.url));
  const ts = new Date().toISOString().replace(/[:.]/g, '-');
  const runDir = join(__dirname, '..', 'results', `run-${ts}`);
  mkdirSync(runDir, { recursive: true });

  const sizesLines = ['N,K,trial,bytes'];
  for (const [n, k] of NK_COMBOS) {
    const r = results.get(`${n},${k}`)!;
    for (let t = 0; t < r.sizes.length; t++) sizesLines.push(`${n},${k},${t},${r.sizes[t]}`);
  }
  writeFileSync(join(runDir, 'sizes.csv'), sizesLines.join('\n') + '\n');

  const summaryLines = ['N,K,mean_bytes,min_bytes,max_bytes'];
  for (const [n, k] of NK_COMBOS) {
    const r = results.get(`${n},${k}`)!;
    summaryLines.push(`${n},${k},${r.mean},${r.min},${r.max}`);
  }
  writeFileSync(join(runDir, 'summary.csv'), summaryLines.join('\n') + '\n');

  writeFileSync(join(runDir, 'fit.json'), JSON.stringify({
    encoding: 'compact_binary_tlv',
    n10_intercept: fitN10.intercept,
    n10_slope: fitN10.slope,
    n10_r2: fitN10.r2,
    n5_intercept: fitN5.intercept,
    n5_slope: fitN5.slope,
    n5_r2: fitN5.r2,
  }, null, 2) + '\n');

  const stdoutContent = [
    'Encoding: compact binary (TLV)',
    '',
    ...NK_COMBOS.map(([n, k]) => { const r = results.get(`${n},${k}`)!; return `N=${n}, K=${k}: mean=${r.mean} min=${r.min} max=${r.max}`; }),
    '',
    `N=10 fit: slope=${fitN10.slope.toFixed(1)}, intercept=${fitN10.intercept.toFixed(1)}, R²=${fitN10.r2.toFixed(4)}`,
    `N=5 fit: slope=${fitN5.slope.toFixed(1)}, intercept=${fitN5.intercept.toFixed(1)}, R²=${fitN5.r2.toFixed(4)}`,
    '',
    pgfplot,
  ];
  writeFileSync(join(runDir, 'stdout.txt'), stdoutContent.join('\n') + '\n');

  console.log(`\nResults saved to ${runDir}/`);
}

main();
