/**
 * bench.ts — Tamper Detection Suite (Table 6.1)
 *
 * Builds baseline bundles, runs seven tamper mutations,
 * verifies each is detected, and emits LaTeX + JSON results.
 */

import { writeFileSync, mkdirSync, cpSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { performance } from 'node:perf_hooks';

import { TxStore } from './regtest.js';
import { buildBaseline } from './baseline.js';
import { verifyBundle, type VerifyResult } from './verify.js';
import { bytesToHex } from './crypto.js';
import type { DisclosureBundle, Baseline } from './types.js';
import {
  tm1_postHocFabrication,
  tm2_fieldValueManipulation,
  tm3_fieldManipulationNewProof,
  tm4_signatureReplay,
  tm5_forgedMerchantSig,
  tm6_wrongInternalKey,
  tm7_swappedNonce,
} from './attacks.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

interface AttackDef {
  id: string;
  label: string;
  expectedStep: 1 | 2 | 3 | 4 | 5 | 6;
  mutate: (bl1: Baseline, bl2: Baseline) => DisclosureBundle;
}

const ATTACKS: AttackDef[] = [
  { id: 'TM1', label: 'Post-hoc invoice fabrication',      expectedStep: 4, mutate: (bl1) => tm1_postHocFabrication(bl1) },
  { id: 'TM2', label: 'Field value manipulation (amount)',  expectedStep: 3, mutate: (bl1) => tm2_fieldValueManipulation(bl1) },
  { id: 'TM3', label: 'Field manipulation + recomputed proof', expectedStep: 4, mutate: (bl1) => tm3_fieldManipulationNewProof(bl1) },
  { id: 'TM4', label: 'Signature replay (wrong txid)',      expectedStep: 6, mutate: (bl1, bl2) => tm4_signatureReplay(bl1, bl2) },
  { id: 'TM5', label: 'Forged merchant signature',          expectedStep: 5, mutate: (bl1) => tm5_forgedMerchantSig(bl1) },
  { id: 'TM6', label: 'Wrong internal key',                 expectedStep: 4, mutate: (bl1) => tm6_wrongInternalKey(bl1) },
  { id: 'TM7', label: 'Swapped blinding nonce',             expectedStep: 3, mutate: (bl1) => tm7_swappedNonce(bl1) },
];

function serializeBundle(b: DisclosureBundle): string {
  return JSON.stringify({
    txid: bytesToHex(b.txid),
    recipientScript: bytesToHex(b.recipientScript),
    disclosedIndices: b.disclosedIndices,
    disclosedFields: b.disclosedFields.map(df => ({
      name: df.name,
      value: bytesToHex(df.value),
      nonce: bytesToHex(df.nonce),
      proof: df.proof.map(p => bytesToHex(p)),
    })),
    merkleRoot: bytesToHex(b.merkleRoot),
    internalPub: bytesToHex(b.internalPub),
    outputPub: bytesToHex(b.outputPub),
    merchantSignature: bytesToHex(b.merchantSignature),
    merchantPub: bytesToHex(b.merchantPub),
    intentSignature: bytesToHex(b.intentSignature),
    intentMessage: bytesToHex(b.intentMessage),
    payerPub: bytesToHex(b.payerPub),
  }, null, 2);
}

function saveBaselineArtifacts(dir: string, bl: Baseline): void {
  mkdirSync(dir, { recursive: true });

  writeFileSync(join(dir, 'sbi.json'), JSON.stringify({
    fields: bl.fields.map((f, i) => ({
      name: f.name,
      value: bytesToHex(f.value),
      nonce: bytesToHex(bl.nonces[i]),
    })),
  }, null, 2) + '\n');

  writeFileSync(join(dir, 'merkle.json'), JSON.stringify({
    root: bytesToHex(bl.tree.root),
    leaves: bl.tree.leaves.map(l => bytesToHex(l)),
    layerCount: bl.tree.layers.length,
  }, null, 2) + '\n');

  writeFileSync(join(dir, 'keys.json'), JSON.stringify({
    merchantPriv: bytesToHex(bl.merchantPriv),
    merchantPub: bytesToHex(bl.merchantPub),
    internalPriv: bytesToHex(bl.internalPriv),
    internalPub: bytesToHex(bl.internalPub),
    outputPub: bytesToHex(bl.outputPub),
    tweakedPriv: bytesToHex(bl.tweakedPriv),
    payerPriv: bytesToHex(bl.payerPriv),
    payerPub: bytesToHex(bl.payerPub),
  }, null, 2) + '\n');

  writeFileSync(join(dir, 'tx.hex'), bl.txHex + '\n');
  writeFileSync(join(dir, 'txid.txt'), bytesToHex(bl.txid) + '\n');
  writeFileSync(join(dir, 'bundle.json'), serializeBundle(bl.bundle) + '\n');
  writeFileSync(join(dir, 'intent.json'), JSON.stringify({
    intentMessage: bytesToHex(bl.intentMessage),
    intentSignature: bytesToHex(bl.intentSignature),
    disclosedIndices: bl.disclosedIndices,
  }, null, 2) + '\n');
}

function main(): void {
  const t0 = performance.now();
  const txStore = new TxStore();
  const heightBefore = txStore.getBlockHeight();
  const output: string[] = [];

  function log(msg: string): void {
    console.log(msg);
    output.push(msg);
  }

  // ── Phase A: Build baseline 1 ────────────────────────────────────────
  log('=== Tamper Detection Suite (Table 6.1) ===\n');
  log('--- Phase A: Baseline Construction ---');

  const bl1 = buildBaseline(txStore);
  const bl1TxidHex = bytesToHex(bl1.txid);
  log(`Baseline 1: txid=${bl1TxidHex.slice(0, 16)}...`);
  log(`  Confirmed at height ${txStore.lookup(bl1TxidHex)?.blockHeight}`);

  // Verify baseline ACCEPT
  const baselineResult = verifyBundle(bl1.bundle, txStore);
  if (!baselineResult.accept) {
    log(`\nFATAL: Baseline verification FAILED at step ${(baselineResult as any).failedAt}: ${(baselineResult as any).reason}`);
    log('Cannot proceed. The baseline is broken.');
    process.exit(1);
  }
  log('Baseline 1 verification: ACCEPT');

  // Save baseline 1 artifacts
  const baselineDir = join(__dirname, '..', 'baseline');
  saveBaselineArtifacts(baselineDir, bl1);

  // ── Phase A2: Build baseline 2 (for TM4) ─────────────────────────────
  const bl2 = buildBaseline(txStore);
  const bl2TxidHex = bytesToHex(bl2.txid);
  log(`Baseline 2: txid=${bl2TxidHex.slice(0, 16)}...  [for TM4]`);
  log(`  Confirmed at height ${txStore.lookup(bl2TxidHex)?.blockHeight}`);

  const baseline2Result = verifyBundle(bl2.bundle, txStore);
  if (!baseline2Result.accept) {
    log(`\nFATAL: Baseline 2 verification FAILED.`);
    process.exit(1);
  }
  log('Baseline 2 verification: ACCEPT');

  const baseline2Dir = join(__dirname, '..', 'baseline2');
  saveBaselineArtifacts(baseline2Dir, bl2);

  // ── Setup confirmation ──────────────────────────────────────────────
  log('\n--- Setup Confirmation ---');
  log(`Simulated chain: blocks=${txStore.getBlockHeight()}`);
  log(`Baseline 1: txid=${bl1TxidHex}`);
  log(`Baseline 2: txid=${bl2TxidHex}`);
  log('Baseline verification: ACCEPT (no false positive)\n');

  // ── Phase B: Run seven attacks ──────────────────────────────────────
  log('--- Phase B: Tamper Attacks ---\n');

  interface AttackResult {
    id: string;
    label: string;
    expected: number;
    observed: number | null;
    status: 'PASS' | 'FAIL-EXP-MISMATCH' | 'FAIL-FALSE-NEG';
    reason: string;
  }

  const results: AttackResult[] = [];
  const mutatedBundles: Map<string, string> = new Map();

  for (const attack of ATTACKS) {
    const mutatedBundle = attack.mutate(bl1, bl2);
    const result = verifyBundle(mutatedBundle, txStore);

    mutatedBundles.set(attack.id, serializeBundle(mutatedBundle));

    if (result.accept) {
      results.push({
        id: attack.id,
        label: attack.label,
        expected: attack.expectedStep,
        observed: null,
        status: 'FAIL-FALSE-NEG',
        reason: 'verifier ACCEPTed a tampered bundle!',
      });
    } else {
      const failedAt = result.failedAt;
      const status = failedAt === attack.expectedStep ? 'PASS' : 'FAIL-EXP-MISMATCH';
      results.push({
        id: attack.id,
        label: attack.label,
        expected: attack.expectedStep,
        observed: failedAt,
        status,
        reason: result.reason,
      });
    }
  }

  // ── Check for false negatives ──────────────────────────────────────
  const falseNegs = results.filter(r => r.status === 'FAIL-FALSE-NEG');
  if (falseNegs.length > 0) {
    log('FATAL: FALSE NEGATIVE DETECTED');
    for (const fn of falseNegs) {
      log(`  ${fn.id}: verifier ACCEPTed tampered bundle. This is a VERIFIER BUG.`);
    }
    log('\nStopping. Fix the verifier before producing any results.');
    process.exit(1);
  }

  // ── Print per-attack results ──────────────────────────────────────
  const pad = (s: string, n: number) => s.padEnd(n);
  const maxLabel = Math.max(...results.map(r => r.label.length));

  for (const r of results) {
    log(
      `${r.id} ${pad(r.label, maxLabel + 2)}` +
      `Expected: Step ${r.expected}   ` +
      `Observed: Step ${r.observed}   ` +
      r.status +
      (r.status === 'FAIL-EXP-MISMATCH' ? ` (still rejects, but at different step)` : '')
    );
  }

  const detected = results.filter(r => r.status !== 'FAIL-FALSE-NEG').length;
  const matching = results.filter(r => r.status === 'PASS').length;
  const mismatched = results.filter(r => r.status === 'FAIL-EXP-MISMATCH');

  log(`\nSummary: ${results.length} attacks, ${detected} detected, ${falseNegs.length} false negatives.`);
  log(`Step-ordering matches: ${matching} / ${results.length}` +
    (mismatched.length > 0
      ? `  (${mismatched.map(m => `${m.id} detected at Step ${m.observed} instead of Step ${m.expected}`).join('; ')})`
      : ''));

  // ── LaTeX tabular ────────────────────────────────────────────────
  log('\n--- LaTeX Table 6.1 ---\n');

  const latexRows = results.map(r => {
    const checkOrNote = r.status === 'PASS'
      ? `\\checkmark FAIL Step ${r.observed}`
      : `\\checkmark FAIL Step ${r.observed}\\textsuperscript{*}`;
    return `${r.id} & ${r.label.replace(/&/g, '\\&')} & Step ${r.expected} & ${checkOrNote} \\\\`;
  });

  const latex = [
    '\\begin{tabular}{llll}',
    '\\toprule',
    'ID  & Attack & Expected fail & Result \\\\',
    '\\midrule',
    ...latexRows,
    '\\bottomrule',
    '\\end{tabular}',
  ];

  if (mismatched.length > 0) {
    latex.push('');
    latex.push('\\vspace{0.5em}');
    for (const m of mismatched) {
      latex.push(`\\textsuperscript{*}\\,${m.id}: detected at Step ${m.observed} (expected Step ${m.expected}); ${m.reason}.`);
    }
  }

  const latexStr = latex.join('\n');
  log(latexStr);

  // ── Suggested prose update ──────────────────────────────────────
  log('\n--- Suggested Prose Update ---\n');
  if (matching === results.length) {
    log('Current assertion is accurate: "All seven attacks were detected by the expected');
    log('verification step, with no false negatives."');
  } else {
    log('CORRECTION NEEDED. Suggested replacement:');
    log(`"All seven attacks were detected with no false negatives. ${matching} of ${results.length} were`);
    log(`detected at the expected step; ${mismatched.length} were detected at a different step`);
    log(`(${mismatched.map(m => `${m.id} at Step ${m.observed}`).join(', ')})."`);
  }
  log('');
  log('Append: "The unmutated baseline bundle was verified once and ACCEPTed, confirming');
  log('no false positive on a well-formed bundle."');

  // ── Reproducibility info ──────────────────────────────────────────
  const t1 = performance.now();
  const heightAfter = txStore.getBlockHeight();
  const runDuration = ((t1 - t0) / 1000).toFixed(1);

  log('\n--- Reproducibility ---\n');
  log(`Simulated block height before run: ${heightBefore}`);
  log(`Simulated block height after run:  ${heightAfter} (${heightAfter - heightBefore} blocks mined)`);
  log(`Baseline txid 1: ${bl1TxidHex}`);
  log(`Baseline txid 2: ${bl2TxidHex}`);
  log(`Run duration: ${runDuration} seconds`);

  // ── Save results to disk ──────────────────────────────────────────
  const ts = new Date().toISOString().replace(/[:.]/g, '-');
  const runDir = join(__dirname, '..', 'results', `run-${ts}`);
  mkdirSync(join(runDir, 'mutated-bundles'), { recursive: true });

  // results.json
  writeFileSync(join(runDir, 'results.json'), JSON.stringify(
    results.map(r => ({
      id: r.id,
      label: r.label,
      expected: r.expected,
      observed: r.observed,
      status: r.status,
      reason: r.reason,
    })),
    null, 2
  ) + '\n');

  // stdout.txt
  writeFileSync(join(runDir, 'stdout.txt'), output.join('\n') + '\n');

  // Mutated bundles
  for (const [id, json] of mutatedBundles) {
    writeFileSync(join(runDir, 'mutated-bundles', `${id}.json`), json + '\n');
  }

  // Copy baseline artifacts
  mkdirSync(join(runDir, 'baseline'), { recursive: true });
  mkdirSync(join(runDir, 'baseline2'), { recursive: true });
  try {
    cpSync(baselineDir, join(runDir, 'baseline'), { recursive: true });
    cpSync(baseline2Dir, join(runDir, 'baseline2'), { recursive: true });
  } catch {
    // cpSync may not be available in all Node versions; non-critical
  }

  log(`\nResults saved to ${runDir}/`);

  // ── Determinism check (second run) ────────────────────────────────
  log('\n--- Determinism Check ---\n');

  const txStore2 = new TxStore();
  const bl1b = buildBaseline(txStore2);
  const bl2b = buildBaseline(txStore2);

  const results2: { id: string; observed: number | null }[] = [];
  for (const attack of ATTACKS) {
    const mutated = attack.mutate(bl1b, bl2b);
    const res = verifyBundle(mutated, txStore2);
    results2.push({
      id: attack.id,
      observed: res.accept ? null : res.failedAt,
    });
  }

  let deterministic = true;
  for (let i = 0; i < results.length; i++) {
    if (results[i].observed !== results2[i].observed) {
      log(`NONDETERMINISM: ${results[i].id} — run1: Step ${results[i].observed}, run2: Step ${results2[i].observed}`);
      deterministic = false;
    }
  }
  if (deterministic) {
    log('Determinism check: PASS (all 7 attacks produce identical results across runs)');
  } else {
    log('Determinism check: FAIL — investigate nondeterminism before using these results');
  }
}

main();
