/**
 * crypto.ts — Shared cryptographic primitives.
 *
 * Reuses the exact algorithms from bench-e2e:
 * - Tagged hash (BIP-340 style)
 * - Leaf hash: H("SBI/Leaf", fieldName || fieldValue || nonce)
 * - Merkle tree: H("SBI/Branch", left || right), duplicate-last for odd
 * - Merkle proof generation and verification
 */

import { sha256 } from '@noble/hashes/sha256';
import { concatBytes } from '@noble/hashes/utils';

const te = new TextEncoder();

export function taggedHash(tag: string, ...data: Uint8Array[]): Uint8Array {
  const tagH = sha256(te.encode(tag));
  return sha256(concatBytes(tagH, tagH, ...data));
}

export function computeLeaf(fieldName: string, fieldValue: Uint8Array, nonce: Uint8Array): Uint8Array {
  return taggedHash('SBI/Leaf', te.encode(fieldName), fieldValue, nonce);
}

export interface MerkleTree {
  root: Uint8Array;
  leaves: Uint8Array[];
  layers: Uint8Array[][];
}

export function buildMerkleTree(leaves: Uint8Array[]): MerkleTree {
  if (leaves.length === 0) throw new Error('empty leaves');
  const layers: Uint8Array[][] = [leaves.slice()];
  let current = leaves.slice();
  while (current.length > 1) {
    const next: Uint8Array[] = [];
    for (let i = 0; i < current.length; i += 2) {
      const left = current[i];
      const right = i + 1 < current.length ? current[i + 1] : current[i];
      next.push(taggedHash('SBI/Branch', left, right));
    }
    layers.push(next);
    current = next;
  }
  return { root: current[0], leaves, layers };
}

export function getMerkleProof(tree: MerkleTree, index: number): Uint8Array[] {
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

export function verifyMerkleProof(leaf: Uint8Array, proof: Uint8Array[], root: Uint8Array): boolean {
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

export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

export function bytesToHex(b: Uint8Array): string {
  return Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');
}

export function hexToBytes(hex: string): Uint8Array {
  const a = new Uint8Array(hex.length / 2);
  for (let i = 0; i < a.length; i++) a[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return a;
}
