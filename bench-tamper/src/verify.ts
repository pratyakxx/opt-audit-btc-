/**
 * verify.ts — 6-step auditor verifier with structured error results.
 *
 * Enhanced from bench-e2e to:
 * 1. Return VerifyResult (accept/failedAt) instead of ok/step
 * 2. Check txid binding in Step 6 (prevents TM4 signature replay)
 *
 * Step ordering (must match thesis Table 6.1):
 *   1. txid format + lookup
 *   2. recipient script check
 *   3. Merkle proof check
 *   4. key-tweak recompute
 *   5. merchant signature verify
 *   6. intent signature verify (+ txid binding)
 */

import { schnorr } from '@noble/curves/secp256k1';
import {
  pubSchnorr,
  taprootTweakPubkey,
} from '@scure/btc-signer/utils';
import { p2tr, NETWORK } from '@scure/btc-signer';
import {
  taggedHash,
  computeLeaf,
  verifyMerkleProof,
  equalBytes,
  bytesToHex,
} from './crypto.js';
import type { DisclosureBundle } from './types.js';
import type { TxStore } from './regtest.js';

export type VerifyResult =
  | { accept: true }
  | { accept: false; failedAt: 1 | 2 | 3 | 4 | 5 | 6; reason: string };

export function verifyBundle(bundle: DisclosureBundle, txStore: TxStore): VerifyResult {
  // Step 1: txid format + lookup
  const txidHex = bytesToHex(bundle.txid);
  if (bundle.txid.length !== 32)
    return { accept: false, failedAt: 1, reason: 'invalid txid length' };
  const txData = txStore.lookup(txidHex);
  if (!txData)
    return { accept: false, failedAt: 1, reason: 'txid not found' };
  if (!txData.confirmed)
    return { accept: false, failedAt: 1, reason: 'tx not confirmed' };

  // Step 2: recipient script check
  if (!equalBytes(bundle.recipientScript, txData.recipientScript))
    return { accept: false, failedAt: 2, reason: 'recipient script mismatch' };

  // Step 3: Merkle proof check for each revealed field
  for (const df of bundle.disclosedFields) {
    const leaf = computeLeaf(df.name, df.value, df.nonce);
    if (!verifyMerkleProof(leaf, df.proof, bundle.merkleRoot))
      return { accept: false, failedAt: 3, reason: `Merkle proof failed for field "${df.name}"` };
  }

  // Step 4: key-tweak recompute
  const [recomputedOutputPub] = taprootTweakPubkey(bundle.internalPub, bundle.merkleRoot);
  if (!equalBytes(recomputedOutputPub, bundle.outputPub))
    return { accept: false, failedAt: 4, reason: 'output key mismatch (tweak recompute)' };
  const expectedPayment = p2tr(bundle.outputPub, undefined, NETWORK);
  if (!equalBytes(expectedPayment.script, txData.outputScript))
    return { accept: false, failedAt: 4, reason: 'output script mismatch on-chain' };

  // Step 5: merchant signature verify
  if (!schnorr.verify(bundle.merchantSignature, bundle.merkleRoot, bundle.merchantPub))
    return { accept: false, failedAt: 5, reason: 'merchant signature invalid' };

  // Step 6: intent signature verify + txid binding
  // Recompute expected intent hash from the bundle's txid and disclosed indices
  const idxBytes = new Uint8Array(bundle.disclosedIndices.slice().sort((a, b) => a - b));
  const expectedIntent = taggedHash('SBI/Intent', bundle.txid, idxBytes);
  if (!equalBytes(bundle.intentMessage, expectedIntent))
    return { accept: false, failedAt: 6, reason: 'intent message does not bind to claimed txid' };
  if (!schnorr.verify(bundle.intentSignature, bundle.intentMessage, bundle.payerPub))
    return { accept: false, failedAt: 6, reason: 'intent signature invalid' };

  return { accept: true };
}
