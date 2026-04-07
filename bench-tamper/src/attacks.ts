/**
 * attacks.ts — Seven tamper mutations for Table 6.1.
 *
 * Each function takes a baseline (and optionally baseline2 for TM4)
 * and returns a mutated DisclosureBundle.
 */

import { schnorr } from '@noble/curves/secp256k1';
import { randomPrivateKeyBytes, pubSchnorr } from '@scure/btc-signer/utils';
import {
  taggedHash,
  computeLeaf,
  buildMerkleTree,
  getMerkleProof,
} from './crypto.js';
import type { DisclosureBundle, Baseline } from './types.js';

const te = new TextEncoder();

function randomBytes(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

function uint64Bytes(n: bigint): Uint8Array {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, n, false);
  return b;
}

/**
 * TM1 — Post-hoc invoice fabrication
 * Build an entirely new SBI with different fields, reference baseline's txid.
 * Expected fail: Step 4 (tweak mismatch)
 */
export function tm1_postHocFabrication(bl: Baseline): DisclosureBundle {
  // Fabricate a completely different SBI
  const fakeFields = [
    { name: 'amount',         value: uint64Bytes(999999n) },
    { name: 'currency',       value: te.encode('ETH') },
    { name: 'merchant_did',   value: te.encode('did:key:z6MkFAKE' + '0'.repeat(32)) },
    { name: 'recipient_addr', value: randomBytes(20) },
    { name: 'timestamp',      value: uint64Bytes(BigInt(Math.floor(Date.now() / 1000))) },
    { name: 'evidence_tier',  value: te.encode('PREMIUM') },
    { name: 'memo',           value: te.encode('Fabricated invoice') },
    { name: 'expiry',         value: uint64Bytes(0n) },
    { name: 'network',        value: te.encode('mainnet') },
    { name: 'version',        value: new Uint8Array([0x02]) },
  ];
  const fakeNonces = Array.from({ length: 10 }, () => randomBytes(16));
  const fakeLeaves = fakeFields.map((f, i) => computeLeaf(f.name, f.value, fakeNonces[i]));
  const fakeTree = buildMerkleTree(fakeLeaves);

  const disclosedIndices = [0, 1, 2];
  const fakeDisclosed = disclosedIndices.map(idx => ({
    name: fakeFields[idx].name,
    value: fakeFields[idx].value,
    nonce: fakeNonces[idx],
    proof: getMerkleProof(fakeTree, idx),
  }));

  return {
    ...bl.bundle,
    disclosedFields: fakeDisclosed,
    disclosedIndices,
    merkleRoot: fakeTree.root,
    // Keep baseline's internalPub, outputPub, txid, recipientScript, sigs
  };
}

/**
 * TM2 — Field value manipulation (amount)
 * Change the amount field's value, leave proof/nonce/root untouched.
 * Expected fail: Step 3 (leaf hash mismatch)
 */
export function tm2_fieldValueManipulation(bl: Baseline): DisclosureBundle {
  const mutatedFields = bl.bundle.disclosedFields.map((df, i) => {
    if (i === 0) {
      // Mutate the first disclosed field's value (amount)
      return { ...df, value: uint64Bytes(9999999n) };
    }
    return df;
  });

  return {
    ...bl.bundle,
    disclosedFields: mutatedFields,
  };
}

/**
 * TM3 — Field manipulation + recomputed proof
 * Change amount AND rebuild the Merkle tree with new proofs and root.
 * Keep baseline's sigs and txid.
 * Expected fail: Step 4 (tweak mismatch) or Step 5 (merchant sig)
 */
export function tm3_fieldManipulationNewProof(bl: Baseline): DisclosureBundle {
  // Build a new SBI with mutated amount
  const mutatedFields = bl.fields.map((f, i) => {
    if (i === 0) return { ...f, value: uint64Bytes(9999999n) };
    return f;
  });
  const mutatedLeaves = mutatedFields.map((f, i) =>
    computeLeaf(f.name, f.value, bl.nonces[i])
  );
  const mutatedTree = buildMerkleTree(mutatedLeaves);

  const disclosedIndices = bl.disclosedIndices;
  const newDisclosed = disclosedIndices.map(idx => ({
    name: mutatedFields[idx].name,
    value: mutatedFields[idx].value,
    nonce: bl.nonces[idx],
    proof: getMerkleProof(mutatedTree, idx),
  }));

  return {
    ...bl.bundle,
    disclosedFields: newDisclosed,
    merkleRoot: mutatedTree.root,
    // Keep baseline's merchantSignature, intentSignature, txid
  };
}

/**
 * TM4 — Signature replay (wrong txid)
 * Use baseline2's intent signature/message with baseline1's txid.
 * Expected fail: Step 6 (intent message doesn't bind to claimed txid)
 */
export function tm4_signatureReplay(bl1: Baseline, bl2: Baseline): DisclosureBundle {
  return {
    ...bl1.bundle,
    // Substitute baseline2's intent sig and message (which bind to bl2.txid)
    intentSignature: bl2.intentSignature,
    intentMessage: bl2.intentMessage,
    payerPub: bl2.payerPub,
  };
}

/**
 * TM5 — Forged merchant signature
 * Sign merkle_root with attacker's key, keep baseline's merchant pubkey.
 * Expected fail: Step 5 (sig doesn't match pubkey)
 */
export function tm5_forgedMerchantSig(bl: Baseline): DisclosureBundle {
  const attackerPriv = randomPrivateKeyBytes();
  const forgedSig = schnorr.sign(bl.tree.root, attackerPriv);

  return {
    ...bl.bundle,
    merchantSignature: forgedSig,
    // Keep merchantPub unchanged — attacker can't substitute it
  };
}

/**
 * TM6 — Wrong internal key
 * Substitute a different internalPub in the bundle.
 * Expected fail: Step 4 (recomputed output key doesn't match on-chain)
 */
export function tm6_wrongInternalKey(bl: Baseline): DisclosureBundle {
  const fakeInternalPriv = randomPrivateKeyBytes();
  const fakeInternalPub = pubSchnorr(fakeInternalPriv);

  return {
    ...bl.bundle,
    internalPub: fakeInternalPub,
    // outputPub stays as baseline's (on-chain), so tweak recompute fails
  };
}

/**
 * TM7 — Swapped blinding nonce
 * Change the nonce on the first disclosed field.
 * Expected fail: Step 3 (leaf hash mismatch)
 */
export function tm7_swappedNonce(bl: Baseline): DisclosureBundle {
  const mutatedFields = bl.bundle.disclosedFields.map((df, i) => {
    if (i === 0) {
      return { ...df, nonce: randomBytes(16) };
    }
    return df;
  });

  return {
    ...bl.bundle,
    disclosedFields: mutatedFields,
  };
}
