export interface InvoiceField {
  name: string;
  value: Uint8Array;
}

export interface MerkleTree {
  root: Uint8Array;
  leaves: Uint8Array[];
  layers: Uint8Array[][];
}

export interface DisclosedField {
  name: string;
  value: Uint8Array;
  nonce: Uint8Array;
  proof: Uint8Array[];   // each entry: [direction_byte(1) || sibling(32)]
}

export interface DisclosureBundle {
  txid: Uint8Array;
  recipientScript: Uint8Array;
  disclosedFields: DisclosedField[];
  disclosedIndices: number[];
  merkleRoot: Uint8Array;
  internalPub: Uint8Array;       // 32-byte x-only
  outputPub: Uint8Array;         // 32-byte x-only (tweaked)
  merchantSignature: Uint8Array; // 64-byte BIP-340
  merchantPub: Uint8Array;       // 32-byte x-only
  intentSignature: Uint8Array;   // 64-byte BIP-340
  intentMessage: Uint8Array;     // 32-byte tagged hash
  payerPub: Uint8Array;          // 32-byte x-only
}

export interface Baseline {
  fields: InvoiceField[];
  nonces: Uint8Array[];
  tree: MerkleTree;
  merchantPriv: Uint8Array;
  merchantPub: Uint8Array;
  internalPriv: Uint8Array;
  internalPub: Uint8Array;
  outputPub: Uint8Array;
  tweakedPriv: Uint8Array;
  recipientPub: Uint8Array;
  recipientScript: Uint8Array;
  outputScript: Uint8Array;
  txid: Uint8Array;
  txHex: string;
  payerPriv: Uint8Array;
  payerPub: Uint8Array;
  intentMessage: Uint8Array;
  intentSignature: Uint8Array;
  disclosedIndices: number[];
  bundle: DisclosureBundle;
}
