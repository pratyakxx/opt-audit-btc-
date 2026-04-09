/**
 * baseline.ts — Build valid baseline bundles for the tamper detection suite.
 *
 * Each baseline:
 * 1. Generates an SBI with N=10 fields
 * 2. Builds Merkle tree
 * 3. Signs merkle_root with merchant key (BIP-340)
 * 4. Computes key tweak (BIP-341) and output key
 * 5. Builds a P2TR transaction (simulated, using @scure/btc-signer)
 * 6. Signs intent message binding txid to disclosed indices
 * 7. Constructs disclosure bundle revealing K=3 fields
 */

import { Transaction, p2tr, NETWORK } from '@scure/btc-signer';
import {
  pubSchnorr,
  taprootTweakPrivKey,
  taprootTweakPubkey,
  randomPrivateKeyBytes,
} from '@scure/btc-signer/utils';
import { schnorr } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import {
  taggedHash,
  computeLeaf,
  buildMerkleTree,
  getMerkleProof,
  bytesToHex,
} from './crypto.js';
import type { InvoiceField, DisclosureBundle, Baseline } from './types.js';
import { TxStore } from './regtest.js';

const te = new TextEncoder();

function randomBytes(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

function uint64Bytes(n: bigint): Uint8Array {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, n, false);
  return b;
}

function generateInvoiceFields(): InvoiceField[] {
  return [
    { name: 'amount',         value: uint64Bytes(BigInt(Math.floor(Math.random() * 1e8))) },
    { name: 'currency',       value: te.encode('BTC') },
    { name: 'merchant_did',   value: te.encode('did:key:z6Mk' + bytesToHex(randomBytes(16))) },
    { name: 'recipient_addr', value: randomBytes(20) },
    { name: 'timestamp',      value: uint64Bytes(BigInt(Math.floor(Date.now() / 1000))) },
    { name: 'evidence_tier',  value: te.encode('STANDARD') },
    { name: 'memo',           value: te.encode('Payment for invoice #' + Math.floor(Math.random() * 1e6)) },
    { name: 'expiry',         value: uint64Bytes(BigInt(Math.floor(Date.now() / 1000) + 3600)) },
    { name: 'network',        value: te.encode('regtest') },
    { name: 'version',        value: new Uint8Array([0x01]) },
  ];
}

export function buildBaseline(txStore: TxStore): Baseline {
  // 1. Generate SBI fields and nonces
  const fields = generateInvoiceFields();
  const nonces = Array.from({ length: 10 }, () => randomBytes(16));

  // 2. Build Merkle tree
  const leaves = fields.map((f, i) => computeLeaf(f.name, f.value, nonces[i]));
  const tree = buildMerkleTree(leaves);

  // 3. Merchant signs merkle_root
  const merchantPriv = randomPrivateKeyBytes();
  const merchantPub = pubSchnorr(merchantPriv);
  const merchantSig = schnorr.sign(tree.root, merchantPriv);

  // 4. Key tweak
  const internalPriv = randomPrivateKeyBytes();
  const internalPub = pubSchnorr(internalPriv);
  const tweakedPriv = taprootTweakPrivKey(internalPriv, tree.root);
  const [outputPub] = taprootTweakPubkey(internalPub, tree.root);

  // 5. Build simulated P2TR transaction
  const recipientPriv = randomPrivateKeyBytes();
  const recipientPub = pubSchnorr(recipientPriv);

  const senderPayment = p2tr(outputPub, undefined, NETWORK);
  const recipientPayment = p2tr(recipientPub, undefined, NETWORK);

  const tx = new Transaction();
  tx.addInput({
    txid: randomBytes(32),
    index: 0,
    witnessUtxo: {
      amount: 100_000n,
      script: senderPayment.script,
    },
    tapInternalKey: internalPub,
    tapMerkleRoot: tree.root,
  });
  tx.addOutput({ script: recipientPayment.script, amount: 50_000n });
  tx.addOutput({ script: senderPayment.script, amount: 49_000n });
  tx.sign(tweakedPriv);
  tx.finalize();

  const raw = tx.extract();
  const txid = sha256(sha256(raw));
  const txHex = bytesToHex(raw);

  // Register in TxStore
  const txidHex = bytesToHex(txid);
  const blockHeight = txStore.register(txidHex, {
    recipientScript: recipientPayment.script,
    outputScript: senderPayment.script,
  });

  // 6. Intent message + sign
  const payerPriv = randomPrivateKeyBytes();
  const payerPub = pubSchnorr(payerPriv);
  const disclosedIndices = [0, 1, 2];
  const idxBytes = new Uint8Array(disclosedIndices);
  const intentMessage = taggedHash('SBI/Intent', txid, idxBytes);
  const intentSig = schnorr.sign(intentMessage, payerPriv);

  // 7. Build disclosure bundle
  const disclosedFields = disclosedIndices.map(idx => ({
    name: fields[idx].name,
    value: fields[idx].value,
    nonce: nonces[idx],
    proof: getMerkleProof(tree, idx),
  }));

  const bundle: DisclosureBundle = {
    txid,
    recipientScript: recipientPayment.script,
    disclosedFields,
    disclosedIndices,
    merkleRoot: tree.root,
    internalPub,
    outputPub,
    merchantSignature: merchantSig,
    merchantPub,
    intentSignature: intentSig,
    intentMessage,
    payerPub,
  };

  return {
    fields,
    nonces,
    tree,
    merchantPriv,
    merchantPub,
    internalPriv,
    internalPub,
    outputPub,
    tweakedPriv,
    recipientPub,
    recipientScript: recipientPayment.script,
    outputScript: senderPayment.script,
    txid,
    txHex,
    payerPriv,
    payerPub,
    intentMessage,
    intentSignature: intentSig,
    disclosedIndices,
    bundle,
  };
}
