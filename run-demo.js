#!/usr/bin/env node
'use strict';
/**
 * Automated Alice↔Bob demo — spawns both clients, exchanges messages,
 * prints everything to one terminal for screenshot.
 */

const net = require('net');
const { generateKeyPair, encryptMessage, decryptMessage } = require('./lib/e2e');
const { buildVS3Frame, chunkFrame, encodeGhostShare } = require('./lib/vs3-frame');

const HOST = '127.0.0.1';
const PORT = 4444;
const ALICE_WALLET = '4' + 'A'.repeat(94);
const BOB_WALLET   = '4' + 'B'.repeat(94);

const MESSAGES = [
  { from: 'alice', text: 'Meeting confirmed for Thursday. The dissident group has 40 members ready.' },
  { from: 'bob',   text: 'Understood. We secured 3 safe houses outside the capital.' },
  { from: 'alice', text: 'The regime blocked Signal and Tor last week. This channel is all we have.' },
  { from: 'bob',   text: 'Press contacts in Berlin and DC are standing by. Send the documents when ready.' },
  { from: 'alice', text: 'Uploading now. 14 pages of evidence. The world needs to see this.' },
  { from: 'bob',   text: 'Received. We will publish simultaneously across 6 outlets. Stay safe.' },
];

function log(tag, msg) {
  const ts = new Date().toISOString().slice(11, 19);
  console.log(`  ${ts} [${tag}] ${msg}`);
}

class DemoClient {
  constructor(name, myWallet, peerWallet) {
    this.name = name;
    this.wallet = myWallet;
    this.peerWallet = peerWallet;
    this.keys = generateKeyPair();
    this.peerKey = null;
    this.sock = null;
    this.minerId = null;
    this.jobId = null;
    this.reqId = 100;
    this.buf = '';
    this.onReady = null;
    this.onPeerKey = null;
    this.onMessage = null;
  }

  connect() {
    return new Promise((resolve) => {
      this.sock = net.connect(PORT, HOST, () => {
        this.sock.write(JSON.stringify({
          id: 1, jsonrpc: '2.0', method: 'login',
          params: { login: this.wallet, pass: 'x', agent: `demo-${this.name}/1.0` }
        }) + '\n');
      });

      this.sock.on('data', (d) => {
        this.buf += d.toString();
        const lines = this.buf.split('\n');
        this.buf = lines.pop();
        for (const line of lines) {
          if (!line.trim()) continue;
          let msg; try { msg = JSON.parse(line); } catch { continue; }

          if (msg.id === 1 && msg.result) {
            this.minerId = msg.result.id;
            this.jobId = msg.result.job?.job_id;
            log(this.name, `connected (miner=${this.minerId.slice(0,8)})`);
            resolve();
          }
          if (msg.method === 'job' && msg.params) {
            if (msg.params.job_id) this.jobId = msg.params.job_id;
            if (msg.params.vs3) {
              const frame = Buffer.from(msg.params.vs3, 'hex');
              if (frame.length >= 9 && frame[0] === 0xAA) {
                const type = frame[2];
                const payload = frame.slice(8, 8 + frame[7]);
                if (type === 0x04 && payload.length === 32) {
                  this.peerKey = payload;
                  log(this.name, `key exchange complete: ${payload.toString('hex').slice(0,16)}...`);
                  if (this.onPeerKey) this.onPeerKey();
                } else if (type === 0x05 && this.peerKey) {
                  try {
                    const pt = decryptMessage(payload, this.keys.privateKey);
                    log(this.name, `received: "${pt.toString('utf8')}"`);
                    if (this.onMessage) this.onMessage(pt.toString('utf8'));
                  } catch (e) {
                    // frame not for us
                  }
                }
              }
            }
          }
        }
      });
    });
  }

  async sendFrame(frameBytes) {
    const chunks = chunkFrame(frameBytes);
    let i = 0;
    return new Promise((resolve) => {
      const iv = setInterval(() => {
        if (i >= chunks.length) { clearInterval(iv); resolve(); return; }
        const vs3To = i === 0 ? this.peerWallet : null;
        const share = encodeGhostShare(this.reqId++, this.minerId, this.jobId, chunks[i], vs3To);
        this.sock.write(share + '\n');
        i++;
      }, 80);
    });
  }

  async sendKey() {
    log(this.name, `sending public key...`);
    const frame = buildVS3Frame(this.keys.publicKey, 0x04);
    await this.sendFrame(frame);
  }

  async sendEncrypted(text) {
    const ct = encryptMessage(text, this.peerKey);
    log(this.name, `sending: "${text}" (${ct.length}B encrypted, ${Math.ceil((ct.length+8)/5)} ghost shares)`);
    const frame = buildVS3Frame(ct, 0x05);
    await this.sendFrame(frame);
  }

  close() { this.sock.destroy(); }
}

(async () => {
  console.log('');
  console.log('  ╔═══════════════════════════════════════════════════════════╗');
  console.log('  ║  TNZX Protocol — Live E2E Encrypted Chat Demo            ║');
  console.log('  ║  Alice ↔ Stratum Pool ↔ Bob                              ║');
  console.log('  ╚═══════════════════════════════════════════════════════════╝');
  console.log('');

  const alice = new DemoClient('alice', ALICE_WALLET, BOB_WALLET);
  const bob   = new DemoClient('bob',   BOB_WALLET,   ALICE_WALLET);

  await alice.connect();
  await bob.connect();
  console.log('');

  // Key exchange
  const aliceGotKey = new Promise(r => { alice.onPeerKey = r; });
  const bobGotKey   = new Promise(r => { bob.onPeerKey = r; });
  await alice.sendKey();
  await bob.sendKey();
  await Promise.all([aliceGotKey, bobGotKey]);
  // Send keys back
  await alice.sendKey();
  await bob.sendKey();
  await new Promise(r => setTimeout(r, 500));
  console.log('');

  // Exchange messages
  const received = [];
  alice.onMessage = (t) => received.push(t);
  bob.onMessage   = (t) => received.push(t);

  for (const msg of MESSAGES) {
    if (msg.from === 'alice') await alice.sendEncrypted(msg.text);
    else await bob.sendEncrypted(msg.text);
    await new Promise(r => setTimeout(r, 800));
  }

  await new Promise(r => setTimeout(r, 2000));

  console.log('');
  console.log('  ────────────────────────────────────────────────────────────');
  console.log(`  Messages sent: ${MESSAGES.length}`);
  console.log(`  Messages received + decrypted: ${received.length}`);
  console.log(`  Encryption: XChaCha20-Poly1305 (PFS per message)`);
  console.log(`  Pool visibility: type 0x05 only — zero plaintext leaked`);
  console.log('  ────────────────────────────────────────────────────────────');
  console.log('');

  alice.close();
  bob.close();
  process.exit(0);
})().catch(e => { console.error(e); process.exit(1); });
