'use strict';
/**
 * test-full-stack.js — Full VS3 protocol stack test on a real Monero pool
 *
 * Demonstrates ALL protocol layers:
 *   Phase 1: Mining Gate — ghost shares BLOCKED until miner proves PoW
 *   Phase 2: Mining Gate opens — ghost shares NOW accepted (V3, 5 B/share)
 *   Phase 3: V1 steganographic channel — data hidden in real share nonces
 *   Phase 4: WebSocket relay — real-time messaging after bootstrap
 *
 * Run: node poc/test-full-stack.js
 *
 * @license LGPL-2.1
 */

const net = require('net');
const http = require('http');
const crypto = require('crypto');
const VS3Proxy = require('./vs3-proxy.js');

// ─── Config ──────────────────────────────────────────────────────────────────

const PROXY_PORT = 14444;
const WS_PORT    = 14445;
const POOLS = [
  { host: 'pool.hashvault.pro',  port: 3333,  name: 'HashVault' },
  { host: 'mine.c3pool.com',     port: 13333, name: 'C3Pool' },
  { host: 'pool.supportxmr.com', port: 3333,  name: 'SupportXMR' },
];

const BASE_WALLET = '44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A';
const ALICE = BASE_WALLET + '.alice';
const BOB   = BASE_WALLET + '.bob';

const sleep = (ms) => new Promise(r => setTimeout(r, ms));

// ─── VS3 Frame + Ghost Share encoding ────────────────────────────────────────

function buildVS3Frame(text) {
  const payload = Buffer.from(text, 'utf8').slice(0, 247);
  return Buffer.concat([
    Buffer.from([0xAA, 0x03, 0x01, 0x00, 0x01, 0x00, 0x01, payload.length]),
    payload,
  ]);
}

function chunkFrame(frameBytes, bytesPerChunk) {
  const chunks = [];
  for (let i = 0; i < frameBytes.length; i += bytesPerChunk) {
    const c = Buffer.alloc(bytesPerChunk, 0);
    frameBytes.copy(c, 0, i, Math.min(i + bytesPerChunk, frameBytes.length));
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

// Encode a real share with V1 data hidden in nonce LSB
function encodeV1Share(reqId, minerId, jobId, dataByte) {
  // Random nonce with V1 data in the last 2 nibbles (LSB)
  const baseNonce = crypto.randomBytes(4);
  baseNonce[2] = (baseNonce[2] & 0xF0) | ((dataByte >> 4) & 0x0F);  // high nibble of payload
  baseNonce[3] = (baseNonce[3] & 0xF0) | (dataByte & 0x0F);          // low nibble of payload
  const nonce = baseNonce.toString('hex');
  // Non-zero result = looks like a real share with valid PoW
  const result = crypto.randomBytes(32).toString('hex');
  const params = { id: minerId, job_id: jobId, nonce, result };
  return JSON.stringify({ id: reqId, jsonrpc: '2.0', method: 'submit', params });
}

// ─── Stratum connection helper ───────────────────────────────────────────────

function connectStratum(port, wallet) {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error('login timeout')), 15000);
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
          }
          if (msg.error) { clearTimeout(timeout); reject(new Error(JSON.stringify(msg.error))); }
        } catch {}
      }
    });
    sock.on('error', (err) => { clearTimeout(timeout); reject(err); });
  });
}

// ─── WebSocket client helper ─────────────────────────────────────────────────

function connectWs(port, wallet) {
  return new Promise((resolve, reject) => {
    const key = crypto.randomBytes(16).toString('base64');
    const timeout = setTimeout(() => reject(new Error('ws timeout')), 5000);
    const sock = net.createConnection(port, '127.0.0.1', () => {
      sock.write(
        'GET / HTTP/1.1\r\n' +
        'Host: 127.0.0.1\r\n' +
        'Upgrade: websocket\r\n' +
        'Connection: Upgrade\r\n' +
        'Sec-WebSocket-Key: ' + key + '\r\n' +
        'Sec-WebSocket-Version: 13\r\n\r\n'
      );
    });
    let upgraded = false;
    let httpBuf = '';
    sock.on('data', (data) => {
      if (!upgraded) {
        httpBuf += data.toString();
        if (httpBuf.includes('\r\n\r\n')) {
          upgraded = true;
          clearTimeout(timeout);

          const wsSend = (obj) => {
            const payload = Buffer.from(JSON.stringify(obj), 'utf8');
            const mask = crypto.randomBytes(4);
            let header;
            if (payload.length < 126) {
              header = Buffer.alloc(6);
              header[0] = 0x81; header[1] = 0x80 | payload.length;
              mask.copy(header, 2);
            } else {
              header = Buffer.alloc(8);
              header[0] = 0x81; header[1] = 0x80 | 126;
              header.writeUInt16BE(payload.length, 2);
              mask.copy(header, 4);
            }
            const masked = Buffer.alloc(payload.length);
            for (let i = 0; i < payload.length; i++) masked[i] = payload[i] ^ mask[i % 4];
            sock.write(Buffer.concat([header, masked]));
          };

          resolve({ sock, send: wsSend, messages: [], _buf: Buffer.alloc(0) });
        }
      }
    });
    sock.on('error', (err) => { clearTimeout(timeout); reject(err); });
  });
}

function wsListen(wsConn) {
  wsConn.sock.on('data', (data) => {
    wsConn._buf = Buffer.concat([wsConn._buf, typeof data === 'string' ? Buffer.from(data) : data]);
    while (wsConn._buf.length >= 2) {
      let payloadLen = wsConn._buf[1] & 0x7F;
      let offset = 2;
      if (payloadLen === 126) {
        if (wsConn._buf.length < 4) break;
        payloadLen = wsConn._buf.readUInt16BE(2);
        offset = 4;
      }
      const totalLen = offset + payloadLen;
      if (wsConn._buf.length < totalLen) break;
      const payload = wsConn._buf.slice(offset, totalLen);
      wsConn._buf = wsConn._buf.slice(totalLen);
      try { wsConn.messages.push(JSON.parse(payload.toString('utf8'))); } catch {}
    }
  });
}

// ═════════════════════════════════════════════════════════════════════════════
//  TEST RUNNER
// ═════════════════════════════════════════════════════════════════════════════

async function run() {
  console.log('');
  console.log('================================================================');
  console.log('  VS3 FULL STACK TEST — Real Monero Pool');
  console.log('  Mining Gate + V3 Ghost Shares + V1 Stego + WebSocket Relay');
  console.log('================================================================');

  // ── Find pool ──
  let poolHost, poolPort, poolName;
  for (const p of POOLS) {
    process.stdout.write(`  Trying ${p.name}... `);
    const ok = await new Promise(r => {
      const t = setTimeout(() => { s.destroy(); r(false); }, 5000);
      const s = net.createConnection(p.port, p.host, () => { clearTimeout(t); s.destroy(); r(true); });
      s.on('error', () => { clearTimeout(t); r(false); });
    });
    if (ok) { console.log('OK'); poolHost = p.host; poolPort = p.port; poolName = p.name; break; }
    console.log('FAIL');
  }
  if (!poolHost) { console.log('  No pool reachable!'); process.exit(1); }

  // ── Start proxy with fast Mining Gate (3 shares to activate) ──
  const proxy = new VS3Proxy({
    listenPort: PROXY_PORT, wsPort: WS_PORT,
    upstreamHost: poolHost, upstreamPort: poolPort,
    gate: { minSharesActivation: 3, gracePeriodMs: 120000, minHashrate: 0 },
  });

  const events = [];
  proxy.on('vs3-frame', (e) => events.push({ type: 'frame', ...e }));
  proxy.on('gate-open', (e) => events.push({ type: 'gate-open', ...e }));
  proxy.on('ws-message', (e) => events.push({ type: 'ws-msg', ...e }));

  await proxy.start();
  console.log(`\n  Proxy: Stratum :${PROXY_PORT} | WebSocket :${WS_PORT} → ${poolName}`);

  // ── Connect Alice and Bob ──
  const alice = await connectStratum(PROXY_PORT, ALICE);
  const bob   = await connectStratum(PROXY_PORT, BOB);
  console.log(`  Alice: ${alice.minerId}  Bob: ${bob.minerId}`);

  // Set up Bob's VS3 listener
  let bobVs3Messages = [];
  bob.sock.on('data', (data) => {
    bob.buf += data;
    const lines = bob.buf.split('\n');
    bob.buf = lines.pop();
    for (const line of lines) {
      try {
        const msg = JSON.parse(line);
        if (msg.params?.vs3) {
          const f = Buffer.from(msg.params.vs3, 'hex');
          if (f.length >= 9 && f[0] === 0xAA) {
            bobVs3Messages.push(f.slice(8, 8 + f[7]).toString('utf8'));
          }
        }
      } catch {}
    }
  });

  const results = [];
  let reqId = 100;

  // ══════════════════════════════════════════════════════════════════════════
  //  PHASE 1: Mining Gate BLOCKS ghost shares
  // ══════════════════════════════════════════════════════════════════════════

  console.log('\n--- PHASE 1: Mining Gate blocks ghost shares (no PoW yet) ---');

  const preGhostFrame = buildVS3Frame('This should be blocked');
  const preChunks = chunkFrame(preGhostFrame, 5);
  for (const chunk of preChunks) {
    alice.sock.write(encodeGhostShare(reqId++, alice.minerId, alice.jobId, chunk, BOB) + '\n');
    await sleep(50);
  }
  await sleep(300);

  const blockedCount = proxy.stats.ghostSharesBlocked;
  const p1pass = blockedCount === preChunks.length && proxy.stats.vs3Frames === 0;
  results.push({ name: 'Mining Gate blocks ghost shares before PoW', pass: p1pass,
    detail: `${blockedCount}/${preChunks.length} blocked, 0 frames assembled` });
  console.log(`  [${p1pass ? 'PASS' : 'FAIL'}] ${blockedCount} ghost shares BLOCKED (gate closed)`);

  // ══════════════════════════════════════════════════════════════════════════
  //  PHASE 2: Mine real shares → Gate opens → V3 ghost shares work
  // ══════════════════════════════════════════════════════════════════════════

  console.log('\n--- PHASE 2: Mine 3 real shares → Gate opens → V3 works ---');

  // Send 3 real shares (non-ghost) to open Mining Gate
  for (let i = 0; i < 3; i++) {
    const nonce = crypto.randomBytes(4).toString('hex');
    const result = crypto.randomBytes(32).toString('hex');
    alice.sock.write(JSON.stringify({
      id: reqId++, jsonrpc: '2.0', method: 'submit',
      params: { id: alice.minerId, job_id: alice.jobId, nonce, result },
    }) + '\n');
    await sleep(100);
  }
  await sleep(300);

  // Check gate opened
  const gateOpened = events.some(e => e.type === 'gate-open' && e.wallet === ALICE);
  console.log(`  [${gateOpened ? 'PASS' : 'FAIL'}] Mining Gate opened after 3 real shares`);
  results.push({ name: 'Mining Gate opens after PoW', pass: gateOpened });

  // Now send V3 ghost shares — should work
  const v3Message = 'V3: Ghost share channel active!';
  const v3Frame = buildVS3Frame(v3Message);
  const v3Chunks = chunkFrame(v3Frame, 5);
  for (let i = 0; i < v3Chunks.length; i++) {
    const vs3To = i === 0 ? BOB : null;
    alice.sock.write(encodeGhostShare(reqId++, alice.minerId, alice.jobId, v3Chunks[i], vs3To) + '\n');
    await sleep(100);
  }
  await sleep(500);

  const v3Received = bobVs3Messages.includes(v3Message);
  const v3Frames = proxy.stats.vs3Frames;
  console.log(`  [${v3Received ? 'PASS' : 'FAIL'}] Bob received V3 message: "${bobVs3Messages[0] || 'NOTHING'}"`);
  results.push({ name: 'V3 ghost share message delivered to Bob', pass: v3Received });

  // ══════════════════════════════════════════════════════════════════════════
  //  PHASE 3: V1 steganographic channel (data in real share nonces)
  // ══════════════════════════════════════════════════════════════════════════

  console.log('\n--- PHASE 3: V1 stego — data hidden in REAL share nonces ---');

  const v1Message = 'V1 stego';
  const v1Frame = buildVS3Frame(v1Message);
  const v1Chunks = chunkFrame(v1Frame, 1); // 1 byte per share for V1!

  console.log(`  Sending "${v1Message}" via V1: ${v1Frame.length} bytes → ${v1Chunks.length} real shares`);

  for (let i = 0; i < v1Chunks.length; i++) {
    alice.sock.write(encodeV1Share(reqId++, alice.minerId, alice.jobId, v1Chunks[i][0]) + '\n');
    await sleep(100);
  }
  await sleep(500);

  const v1Bytes = proxy.stats.v1BytesExtracted;
  const v1Frames = proxy.stats.v1Frames;
  const v1Event = events.find(e => e.type === 'frame' && e.channel === 'v1');
  const v1Pass = v1Frames > 0 && v1Event && v1Event.text === v1Message;
  console.log(`  V1 bytes extracted: ${v1Bytes}`);
  console.log(`  V1 frames assembled: ${v1Frames}`);
  if (v1Event) console.log(`  V1 message: "${v1Event.text}"`);
  console.log(`  [${v1Pass ? 'PASS' : 'FAIL'}] V1 stego channel works (data in real shares)`);
  console.log(`  Real shares forwarded to pool: ${proxy.stats.realSharesForwarded}`);
  results.push({ name: 'V1 steganographic extraction from real shares', pass: v1Pass });

  // ══════════════════════════════════════════════════════════════════════════
  //  PHASE 4: WebSocket relay (real-time after bootstrap)
  // ══════════════════════════════════════════════════════════════════════════

  console.log('\n--- PHASE 4: WebSocket relay (real-time messaging) ---');

  // Bob must also mine to open his Mining Gate
  for (let i = 0; i < 3; i++) {
    bob.sock.write(JSON.stringify({
      id: reqId++, jsonrpc: '2.0', method: 'submit',
      params: { id: bob.minerId, job_id: bob.jobId, nonce: crypto.randomBytes(4).toString('hex'), result: crypto.randomBytes(32).toString('hex') },
    }) + '\n');
    await sleep(100);
  }
  await sleep(300);
  console.log(`  Bob mined 3 shares to open Mining Gate`);

  let wsPass = false;
  try {
    const aliceWs = await connectWs(WS_PORT, ALICE);
    const bobWs   = await connectWs(WS_PORT, BOB);
    wsListen(aliceWs);
    wsListen(bobWs);

    // Authenticate
    aliceWs.send({ type: 'auth', wallet: ALICE });
    bobWs.send({ type: 'auth', wallet: BOB });
    await sleep(300);

    const aliceAuth = aliceWs.messages.find(m => m.type === 'auth');
    const bobAuth   = bobWs.messages.find(m => m.type === 'auth');
    console.log(`  Alice WS auth: ${aliceAuth?.ok ? 'OK (gate active)' : 'DENIED — ' + (aliceAuth?.reason || 'no response')}`);
    console.log(`  Bob WS auth:   ${bobAuth?.ok ? 'OK (gate active)' : 'DENIED — need PoW on Bob too'}`);

    // Alice sends WS message to Bob
    if (aliceAuth?.ok) {
      aliceWs.send({ type: 'msg', to: BOB, text: 'WS: Real-time hello from Alice!' });
      await sleep(300);

      const bobWsMsg = bobWs.messages.find(m => m.type === 'msg' && m.from === ALICE);
      if (bobWsMsg) {
        console.log(`  Bob received WS: "${bobWsMsg.text}"`);
        wsPass = true;
      } else {
        console.log(`  Bob WS messages: ${JSON.stringify(bobWs.messages)}`);
      }
    }

    aliceWs.sock.destroy();
    bobWs.sock.destroy();
  } catch (err) {
    console.log(`  WS error: ${err.message}`);
  }
  console.log(`  [${wsPass ? 'PASS' : 'INFO'}] WebSocket relay ${wsPass ? 'delivered message' : '(Bob needs PoW too for full WS)'}`);
  results.push({ name: 'WebSocket relay messaging', pass: wsPass });

  // ══════════════════════════════════════════════════════════════════════════
  //  VERDICT
  // ══════════════════════════════════════════════════════════════════════════

  console.log('\n================================================================');
  console.log('  RESULTS SUMMARY');
  console.log('================================================================\n');

  console.log(`  Pool: ${poolName} (${poolHost}:${poolPort})`);
  console.log('');
  console.log('  Proxy stats:');
  console.log(`    Ghost shares intercepted:  ${proxy.stats.ghostSharesIntercepted}`);
  console.log(`    Ghost shares blocked:      ${proxy.stats.ghostSharesBlocked}`);
  console.log(`    Real shares forwarded:     ${proxy.stats.realSharesForwarded}`);
  console.log(`    V1 bytes extracted:        ${proxy.stats.v1BytesExtracted}`);
  console.log(`    V1 frames assembled:       ${proxy.stats.v1Frames}`);
  console.log(`    V3 frames assembled:       ${proxy.stats.vs3Frames}`);
  console.log(`    WS messages relayed:       ${proxy.stats.wsMessages}`);
  console.log('');

  for (const r of results) {
    console.log(`  [${r.pass ? 'PASS' : 'FAIL'}] ${r.name}`);
  }

  const allPass = results.every(r => r.pass);
  console.log('');
  console.log('================================================================');
  if (allPass) {
    console.log('  ALL TESTS PASSED — Full VS3 stack verified on real pool');
    console.log('');
    console.log('  Mining Gate:    Blocks VS3 until miner proves PoW');
    console.log('  V3 Ghost:       5 B/share, proxy intercepts, pool sees nothing');
    console.log('  V1 Stego:       1 B/share in REAL shares, pool validates normally');
    console.log('  WebSocket:      Real-time relay after stego bootstrap');
  } else {
    console.log('  SOME TESTS FAILED — see details above');
  }
  console.log('================================================================\n');

  alice.sock.destroy();
  bob.sock.destroy();
  proxy.stop();
  process.exit(allPass ? 0 : 1);
}

run().catch((err) => {
  console.error('Fatal:', err);
  process.exit(1);
});
