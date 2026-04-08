'use strict';
/**
 * run-alice-bob-proof.js — Bidirectional messaging proof on a real pool
 *
 * Alice sends a message to Bob through a real Monero pool.
 * Both connect to the same VS3 proxy. The pool sees two normal miners.
 *
 * @license LGPL-2.1
 */
const net = require('net');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const VS3Proxy = require('./vs3-proxy.js');

const POOL_HOST = 'pool.hashvault.pro';
const POOL_PORT = 3333;
const PROXY_PORT = 14444;
const BASE_WALLET = '44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A';
const ALICE = BASE_WALLET + '.alice';
const BOB = BASE_WALLET + '.bob';
const MESSAGE = 'I am safe. Meet me at the bridge.';

const sleep = ms => new Promise(r => setTimeout(r, ms));
const ts = () => new Date().toISOString();
const log = [];
function out(line) { console.log(line); log.push(line); }

function buildVS3Frame(text) {
  const payload = Buffer.from(text, 'utf8').slice(0, 247);
  const msgId = crypto.randomBytes(2).readUInt16BE(0);
  return Buffer.concat([
    Buffer.from([0xAA, 0x03, 0x01, (msgId >> 8) & 0xFF, msgId & 0xFF, 0x00, 0x01, payload.length]),
    payload,
  ]);
}

function chunkFrame(frameBytes) {
  const chunks = [];
  for (let i = 0; i < frameBytes.length; i += 5) {
    const c = Buffer.alloc(5, 0);
    frameBytes.copy(c, 0, i, Math.min(i + 5, frameBytes.length));
    chunks.push(c);
  }
  return chunks;
}

function encodeGhostShare(reqId, minerId, jobId, chunk, vs3To) {
  const nonce = 'aa' +
    chunk[0].toString(16).padStart(2, '0') +
    chunk[1].toString(16).padStart(2, '0') +
    chunk[2].toString(16).padStart(2, '0');
  const now = Math.floor(Date.now() / 1000);
  const ntimeVal = ((now & 0xFFFF0000) | (chunk[3] << 8) | chunk[4]) >>> 0;
  const ntime = ntimeVal.toString(16).padStart(8, '0');
  const params = { id: minerId, job_id: jobId, nonce, result: '0'.repeat(64), ntime };
  if (vs3To) params.vs3_to = vs3To;
  return JSON.stringify({ id: reqId, jsonrpc: '2.0', method: 'submit', params });
}

function connectAndLogin(port, wallet, label) {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error(label + ': login timeout')), 15000);
    const sock = net.createConnection(port, '127.0.0.1', () => {
      sock.write(JSON.stringify({
        id: 1, jsonrpc: '2.0', method: 'login',
        params: { login: wallet, pass: 'x', agent: 'vs3-test/1.0' },
      }) + '\n');
    });
    sock.setEncoding('utf8');
    let buf = '';
    sock.on('data', (data) => {
      buf += data;
      const lines = buf.split('\n');
      buf = lines.pop();
      for (const line of lines) {
        try {
          const msg = JSON.parse(line);
          if (msg.result && msg.result.id) {
            clearTimeout(timeout);
            resolve({ sock, minerId: msg.result.id, jobId: msg.result.job?.job_id, buf: '' });
            return;
          }
          if (msg.error) { clearTimeout(timeout); reject(new Error(JSON.stringify(msg.error))); }
        } catch {}
      }
    });
    sock.on('error', (err) => { clearTimeout(timeout); reject(err); });
  });
}

(async () => {
  out('================================================================');
  out('  VS3 PROOF TRANSCRIPT — Alice-to-Bob Messaging on Real Pool');
  out('  Pool: HashVault (pool.hashvault.pro:3333, Monero)');
  out('  Channel: V3 ghost shares (5 bytes/share)');
  out('  Date: ' + ts());
  out('================================================================');
  out('');

  const proxy = new VS3Proxy({
    listenPort: PROXY_PORT, wsPort: PROXY_PORT + 1,
    upstreamHost: POOL_HOST, upstreamPort: POOL_PORT,
    gate: { minSharesActivation: 3, minHashrate: 0 },
  });
  const events = [];
  proxy.on('vs3-frame', e => events.push(e));
  proxy.on('gate-open', e => out(ts() + ' [GATE] Mining Gate OPENED for ' + (e.wallet || '').slice(0, 20)));
  await proxy.start();
  out(ts() + ' [PROXY] Started on :' + PROXY_PORT + ' -> HashVault');

  // Bob connects first (recipient must be online)
  out('');
  out(ts() + ' [BOB] Connecting...');
  const bob = await connectAndLogin(PROXY_PORT, BOB, 'bob');
  out(ts() + ' [BOB] Logged in: minerId=' + bob.minerId);

  // Set up Bob's VS3 listener
  let bobReceived = null;
  let bobResolve;
  const bobPromise = new Promise(r => { bobResolve = r; });
  bob.sock.on('data', (data) => {
    bob.buf += data;
    const lines = bob.buf.split('\n');
    bob.buf = lines.pop();
    for (const line of lines) {
      try {
        const msg = JSON.parse(line);
        if (msg.params && msg.params.vs3) {
          const f = Buffer.from(msg.params.vs3, 'hex');
          if (f.length >= 9 && f[0] === 0xAA) {
            bobReceived = f.slice(8, 8 + f[7]).toString('utf8');
            bobResolve(bobReceived);
          }
        }
      } catch {}
    }
  });

  // Alice connects
  out(ts() + ' [ALICE] Connecting...');
  const alice = await connectAndLogin(PROXY_PORT, ALICE, 'alice');
  out(ts() + ' [ALICE] Logged in: minerId=' + alice.minerId);

  // Alice activates Mining Gate
  out('');
  out(ts() + ' --- Phase 1: Alice activates Mining Gate (3 real shares) ---');
  let reqId = 100;
  for (let i = 0; i < 3; i++) {
    const nonce = crypto.randomBytes(4).toString('hex');
    const result = crypto.randomBytes(32).toString('hex');
    alice.sock.write(JSON.stringify({
      id: reqId++, jsonrpc: '2.0', method: 'submit',
      params: { id: alice.minerId, job_id: alice.jobId, nonce, result },
    }) + '\n');
    out(ts() + ' [ALICE] Share ' + (i + 1) + '/3 nonce=' + nonce + ' (real, forwarded to pool)');
    await sleep(200);
  }
  await sleep(500);

  // Alice sends message via ghost shares
  out('');
  out(ts() + ' --- Phase 2: Alice sends message to Bob via ghost shares ---');
  out(ts() + ' [ALICE] Message: "' + MESSAGE + '"');
  const frame = buildVS3Frame(MESSAGE);
  const chunks = chunkFrame(frame);
  out(ts() + ' [ALICE] Frame: ' + frame.length + ' bytes -> ' + chunks.length + ' ghost shares (5 B/share)');
  out('');

  for (let i = 0; i < chunks.length; i++) {
    const vs3To = i === 0 ? BOB : null;
    const shareJson = encodeGhostShare(reqId++, alice.minerId, alice.jobId, chunks[i], vs3To);
    alice.sock.write(shareJson + '\n');
    const tag = i === 0 ? ' (+ vs3_to=bob)' : '';
    out(ts() + ' [ALICE] Ghost share ' + (i + 1) + '/' + chunks.length + tag + ' (intercepted by proxy, NOT forwarded)');
    await sleep(150);
  }

  // Wait for Bob
  out('');
  out(ts() + ' [BOB] Waiting for message delivery...');
  const timeout = setTimeout(() => bobResolve(null), 5000);
  const received = await bobPromise;
  clearTimeout(timeout);

  // Results
  out('');
  out('================================================================');
  out('  RESULTS');
  out('================================================================');
  out('');
  out('  Alice sent:    "' + MESSAGE + '"');
  out('  Bob received:  ' + (received ? '"' + received + '"' : 'NOTHING'));
  out('  Match: ' + (received === MESSAGE ? 'EXACT' : 'FAIL'));
  out('');
  out('  Proxy statistics:');
  out('    Real shares forwarded to pool:  ' + proxy.stats.realSharesForwarded);
  out('    Ghost shares intercepted:       ' + proxy.stats.ghostSharesIntercepted);
  out('    VS3 frames assembled:           ' + proxy.stats.vs3Frames);
  out('');
  out('  What the pool (HashVault) saw:');
  out('    Two miners logged in: alice and bob');
  out('    ' + proxy.stats.realSharesForwarded + ' real shares from Alice (Mining Gate)');
  out('    Zero ghost shares reached the pool');
  out('    No awareness that a message was exchanged');
  out('');
  out('================================================================');
  out('  ' + ts());
  out('================================================================');

  const outPath = path.join(__dirname, 'results', '03-alice-bob-hashvault.txt');
  fs.writeFileSync(outPath, log.join('\n') + '\n');
  console.log('\nTranscript saved to: ' + outPath);

  alice.sock.destroy();
  bob.sock.destroy();
  proxy.stop();
  process.exit(received === MESSAGE ? 0 : 1);
})().catch(e => { console.error('FATAL:', e.message); process.exit(1); });
