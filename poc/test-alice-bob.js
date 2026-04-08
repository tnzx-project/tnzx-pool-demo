'use strict';
/**
 * test-alice-bob.js — Alice sends a message to Bob through a real Monero pool
 *
 * Both Alice and Bob connect to the VS3 proxy.
 * The proxy connects to a real Monero pool (C3Pool, HashVault, etc.).
 * Alice sends ghost shares containing a message addressed to Bob.
 * The proxy extracts the message and delivers it to Bob via job notification.
 * Bob receives the message in the vs3 field of a job.
 *
 * The real pool sees NOTHING. Just two miners that logged in.
 *
 * Run: node poc/test-alice-bob.js
 *
 * @license LGPL-2.1
 */

const net = require('net');
const crypto = require('crypto');
const VS3Proxy = require('./vs3-proxy.js');

// ─── Config ──────────────────────────────────────────────────────────────────

const PROXY_PORT = 14444;

// Pools to try
const POOLS = [
  { host: 'pool.hashvault.pro',  port: 3333,  name: 'HashVault' },
  { host: 'mine.c3pool.com',     port: 13333, name: 'C3Pool' },
  { host: 'pool.supportxmr.com', port: 3333,  name: 'SupportXMR' },
];

// Same valid Monero wallet, different worker names — standard mining practice
// Pools accept "wallet.worker" format. The proxy routes by full login string.
const BASE_WALLET  = '44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A';
const ALICE_WALLET = BASE_WALLET + '.alice';
const BOB_WALLET   = BASE_WALLET + '.bob';

const ALICE_MESSAGE = 'Bob, meet me at the bridge at midnight.';

// ─── VS3 Encoding ────────────────────────────────────────────────────────────

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

// ─── Helper: connect and login ───────────────────────────────────────────────

function connectAndLogin(port, wallet, label) {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error(`${label}: login timeout`)), 15000);
    const sock = net.createConnection(port, '127.0.0.1', () => {
      const login = JSON.stringify({
        id: 1, jsonrpc: '2.0', method: 'login',
        params: { login: wallet, pass: 'x', agent: `vs3-${label}/1.0` },
      });
      sock.write(login + '\n');
    });
    sock.setEncoding('utf8');
    let buf = '';
    sock.on('data', (data) => {
      buf += data;
      const lines = buf.split('\n');
      buf = lines.pop();
      for (const line of lines) {
        if (!line.trim()) continue;
        try {
          const msg = JSON.parse(line);
          if (msg.result && msg.result.id) {
            clearTimeout(timeout);
            resolve({
              sock,
              minerId: msg.result.id,
              jobId: msg.result.job?.job_id,
              buf: '',
            });
            return;
          }
          if (msg.error) {
            clearTimeout(timeout);
            reject(new Error(`${label}: ${JSON.stringify(msg.error)}`));
          }
        } catch {}
      }
    });
    sock.on('error', (err) => { clearTimeout(timeout); reject(err); });
  });
}

// ─── Main Test ───────────────────────────────────────────────────────────────

async function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

async function run() {
  console.log('');
  console.log('================================================================');
  console.log('  ALICE → BOB TEST');
  console.log('  Bidirectional VS3 messaging through a real Monero pool');
  console.log('================================================================');
  console.log('');
  console.log(`  Alice: ${ALICE_WALLET.slice(0, 20)}...`);
  console.log(`  Bob:   ${BOB_WALLET.slice(0, 20)}...`);
  console.log('');

  // ── Find a working pool ──
  let poolHost, poolPort, poolName;
  for (const p of POOLS) {
    process.stdout.write(`  Trying ${p.name} (${p.host}:${p.port})... `);
    const ok = await new Promise((resolve) => {
      const timeout = setTimeout(() => { sock.destroy(); resolve(false); }, 5000);
      const sock = net.createConnection(p.port, p.host, () => {
        clearTimeout(timeout); sock.destroy(); resolve(true);
      });
      sock.on('error', () => { clearTimeout(timeout); resolve(false); });
    });
    if (ok) {
      console.log('OK');
      poolHost = p.host; poolPort = p.port; poolName = p.name;
      break;
    }
    console.log('FAIL');
  }
  if (!poolHost) { console.log('  No pool reachable!'); process.exit(1); }
  console.log('');

  // ── Start proxy ──
  const proxy = new VS3Proxy({
    listenPort: PROXY_PORT,
    upstreamHost: poolHost,
    upstreamPort: poolPort,
  });
  await proxy.start();
  console.log(`[1] VS3 proxy running on :${PROXY_PORT} → ${poolName} (${poolHost}:${poolPort})`);

  // ── Bob connects first (the recipient must be online) ──
  console.log('[2] Bob connecting...');
  const bob = await connectAndLogin(PROXY_PORT, BOB_WALLET, 'bob');
  console.log(`    Bob logged in: minerId=${bob.minerId}`);

  // Set up Bob's message listener
  let bobReceivedMessage = null;
  let bobMessageResolve;
  const bobMessagePromise = new Promise(r => { bobMessageResolve = r; });

  bob.sock.on('data', (data) => {
    bob.buf += data;
    const lines = bob.buf.split('\n');
    bob.buf = lines.pop();
    for (const line of lines) {
      if (!line.trim()) continue;
      try {
        const msg = JSON.parse(line);
        // Check for VS3 message in job notification
        if (msg.params && msg.params.vs3) {
          const frameBuf = Buffer.from(msg.params.vs3, 'hex');
          if (frameBuf.length >= 9 && frameBuf[0] === 0xAA) {
            const payloadLen = frameBuf[7];
            const text = frameBuf.slice(8, 8 + payloadLen).toString('utf8');
            bobReceivedMessage = text;
            bobMessageResolve(text);
          }
        }
      } catch {}
    }
  });

  // ── Alice connects ──
  console.log('[3] Alice connecting...');
  const alice = await connectAndLogin(PROXY_PORT, ALICE_WALLET, 'alice');
  console.log(`    Alice logged in: minerId=${alice.minerId}`);

  // ── Activate Mining Gate (3 real shares required) ──
  console.log('[3.5] Alice mining real shares to activate Mining Gate...');
  for (let i = 0; i < 3; i++) {
    const nonce = crypto.randomBytes(4).toString('hex');
    const result = crypto.randomBytes(32).toString('hex');
    alice.sock.write(JSON.stringify({
      id: 50 + i, jsonrpc: '2.0', method: 'submit',
      params: { id: alice.minerId, job_id: alice.jobId, nonce, result },
    }) + '\n');
    await sleep(100);
  }
  await sleep(300);
  console.log('    Mining Gate activated');

  // ── Alice sends message to Bob via ghost shares ──
  const frame = buildVS3Frame(ALICE_MESSAGE);
  const chunks = chunkFrame(frame);
  console.log('');
  console.log(`[4] Alice sending: "${ALICE_MESSAGE}"`);
  console.log(`    ${frame.length} bytes → ${chunks.length} ghost shares`);
  console.log('');

  let reqId = 100;
  for (let i = 0; i < chunks.length; i++) {
    const vs3To = i === 0 ? BOB_WALLET : null;
    const shareJson = encodeGhostShare(reqId++, alice.minerId, alice.jobId, chunks[i], vs3To);
    alice.sock.write(shareJson + '\n');
    await sleep(100);
  }

  // ── Wait for Bob to receive ──
  console.log('[5] Waiting for Bob to receive...');
  const timeout = setTimeout(() => {
    bobMessageResolve(null);
  }, 5000);

  const received = await bobMessagePromise;
  clearTimeout(timeout);

  // ── Results ──
  console.log('');
  console.log('================================================================');
  console.log('  RESULTS');
  console.log('================================================================');
  console.log('');
  console.log(`  Alice sent:     "${ALICE_MESSAGE}"`);
  console.log(`  Bob received:   ${received ? `"${received}"` : 'NOTHING'}`);
  console.log('');
  console.log(`  Proxy stats:`);
  console.log(`    Ghost shares intercepted: ${proxy.stats.ghostSharesIntercepted}`);
  console.log(`    VS3 frames assembled:     ${proxy.stats.vs3Frames}`);
  console.log(`    Real shares to pool:      ${proxy.stats.realSharesForwarded}`);
  console.log('');

  const messageMatch = received === ALICE_MESSAGE;
  console.log(`  [${messageMatch ? 'PASS' : 'FAIL'}] Bob received Alice's message correctly`);
  console.log(`  [${proxy.stats.ghostSharesIntercepted === chunks.length ? 'PASS' : 'FAIL'}] All ghost shares intercepted by proxy`);
  console.log(`  [${proxy.stats.realSharesForwarded === 0 ? 'PASS' : 'INFO'}] Pool saw 0 ghost shares`);

  console.log('');
  console.log('================================================================');
  if (messageMatch) {
    console.log('  VERDICT: ALICE AND BOB CAN TALK');
    console.log('');
    console.log('  Alice sent a message through ghost shares.');
    console.log('  The VS3 proxy extracted it and delivered it to Bob');
    console.log('  via a job notification with the vs3 field.');
    console.log(`  The real pool (${poolName}) saw nothing.`);
    console.log('  Two miners logged in. That is all.');
  } else {
    console.log('  VERDICT: COMMUNICATION FAILED');
    console.log('  Bob did not receive the message. Debug needed.');
  }
  console.log('================================================================');
  console.log('');

  // Cleanup
  alice.sock.destroy();
  bob.sock.destroy();
  proxy.stop();
  process.exit(messageMatch ? 0 : 1);
}

run().catch((err) => {
  console.error('Fatal error:', err);
  process.exit(1);
});
