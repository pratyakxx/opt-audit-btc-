/**
 * regtest.ts — Simulated transaction store for the tamper detection suite.
 *
 * Mirrors what a real regtest RPC (getrawtransaction) would return.
 * When regtest config is provided, this can be swapped for actual RPC calls.
 *
 * Regtest config (fill in before connecting to real bitcoind):
 *   RPC URL:    http://localhost:18443
 *   RPC auth:   __cookie__ or user:pass
 *   txindex:    yes (recommended)
 *   Network:    regtest
 */

export interface TxRecord {
  recipientScript: Uint8Array;
  outputScript: Uint8Array;       // the P2TR output containing the commitment
  blockHeight: number;
  confirmed: boolean;
}

export class TxStore {
  private txs = new Map<string, TxRecord>();
  private blockHeight = 100;

  register(txidHex: string, record: Omit<TxRecord, 'blockHeight' | 'confirmed'>): number {
    this.blockHeight++;
    this.txs.set(txidHex, {
      ...record,
      blockHeight: this.blockHeight,
      confirmed: true,
    });
    return this.blockHeight;
  }

  lookup(txidHex: string): TxRecord | undefined {
    return this.txs.get(txidHex);
  }

  getBlockHeight(): number {
    return this.blockHeight;
  }
}
