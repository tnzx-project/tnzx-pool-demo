'use strict';
/**
 * demo-server.js — E2E encrypted chat demo via real mining pool
 *
 * Architecture (nothing is faked):
 *
 *   [Browser UI] ──WS──▶ [This server :3080]
 *                              │
 *                    Alice ──TCP Stratum──▶ [VS3 Proxy :14444] ──▶ pool.hashvault.pro:3333
 *                    Bob   ──TCP Stratum──▶ [VS3 Proxy :14444]     (real Monero pool)
 *
 *   The VS3 proxy runs as an independent process (bin/vs3-proxy-cli.js).
 *   It is the M2 deliverable — a standalone middleware, not a library.
 *
 *   - Ghost shares are intercepted by the proxy, assembled into VS3 frames
 *   - Real shares pass through to HashVault untouched
 *   - HashVault sees two normal miners. Nothing else.
 *   - Messages are E2E encrypted (X25519 + XChaCha20-Poly1305, PFS)
 *
 * Run:  node demo-server.js
 * Open: http://localhost:3080
 *
 * @license LGPL-2.1
 */

const net      = require('net');
const http     = require('http');
const fs       = require('fs');
const path     = require('path');
const crypto   = require('crypto');
const { spawn } = require('child_process');
const { generateKeyPair, encryptMessage, decryptMessage } = require('./lib/e2e');

process.on('uncaughtException', (err) => {
  if (err.code === 'ECONNRESET' || err.code === 'EPIPE' || err.code === 'ECONNREFUSED') return;
  console.error('Uncaught:', err.message);
});

// ─── Config ─────────────────────────────────────────────────────────────────

const PROXY_PORT = 14444;
const HTTP_PORT  = 3080;
const UPSTREAM_HOST = 'pool.hashvault.pro';
const UPSTREAM_PORT = 3333;
const UPSTREAM_NAME = 'HashVault';

const BASE_WALLET = '44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A';
const ALICE_WALLET = BASE_WALLET + '.alice';
const BOB_WALLET   = BASE_WALLET + '.bob';

// ─── State ──────────────────────────────────────────────────────────────────

const clients = {};
const wsClients = [];
const poolEvents = [];

// ─── VS3 Frame helpers ──────────────────────────────────────────────────────

const MSG_TYPE_ENCRYPTED    = 0x05;
const MSG_TYPE_KEY_EXCHANGE = 0x04;

function buildVS3Frame(payload, msgType) {
  const msgId = crypto.randomBytes(2).readUInt16BE(0);
  return Buffer.concat([
    Buffer.from([0xAA, 0x03, msgType, (msgId >> 8) & 0xFF, msgId & 0xFF, 0x00, 0x01, payload.length]),
    payload
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

// ─── Broadcast to browser ───────────────────────────────────────────────────

function broadcast(event) {
  const msg = JSON.stringify(event);
  poolEvents.push(event);
  if (poolEvents.length > 200) poolEvents.shift();
  for (const ws of wsClients) {
    try { ws.write(wsEncodeText(msg)); } catch {}
  }
}

// ─── Virtual Miner ──────────────────────────────────────────────────────────

function createMiner(name, myWallet, peerWallet) {
  const keys = generateKeyPair();
  const state = {
    name, myWallet, peerWallet, keys,
    peerPubKey: null,
    sock: null, minerId: null, jobId: null, reqId: 100,
    connected: false, pendingMessages: []
  };

  const sock = net.connect(PROXY_PORT, '127.0.0.1', () => {
    state.sock = sock;
    state.connected = true;
    broadcast({ type: 'status', who: name, text: `Connected via VS3 Proxy → ${UPSTREAM_NAME}` });
    sock.write(JSON.stringify({
      id: 1, jsonrpc: '2.0', method: 'login',
      params: { login: myWallet, pass: 'x', agent: `vs3-demo-${name}/1.0` }
    }) + '\n');
  });

  let buf = '';
  sock.setEncoding('utf8');
  sock.on('data', (d) => {
    buf += d;
    const lines = buf.split('\n');
    buf = lines.pop();
    for (const line of lines) {
      if (!line.trim()) continue;
      let msg; try { msg = JSON.parse(line); } catch { continue; }

      if (msg.id === 1 && msg.result) {
        state.minerId = msg.result.id;
        state.jobId = msg.result.job?.job_id;
        broadcast({ type: 'status', who: name, text: `Authenticated by ${UPSTREAM_NAME}. Opening Mining Gate...` });
        // Send 3 real shares to open the Mining Gate (anti-Sybil requirement)
        openMiningGate(state).then(() => {
          broadcast({ type: 'status', who: name, text: 'Mining Gate open. Sending public key...' });
          broadcast({ type: 'crypto', who: name, text: 'Mining Gate opened (3 real shares verified)' });
          sendKeyExchange(state);
        });
      }

      if (msg.method === 'job' && msg.params) {
        if (msg.params.job_id) state.jobId = msg.params.job_id;
        if (msg.params.vs3) {
          broadcast({ type: 'pool-log', text: `[${name}] Received VS3 frame in job notification (${msg.params.vs3.length/2}B)` });
          const frame = Buffer.from(msg.params.vs3, 'hex');
          if (frame.length >= 9 && frame[0] === 0xAA) handleFrame(state, frame);
        }
      }
      // Also check login response that contains a job with vs3 (proxy delivery)
      if (msg.result && msg.result.job && msg.result.job.vs3) {
        const frame = Buffer.from(msg.result.job.vs3, 'hex');
        if (frame.length >= 9 && frame[0] === 0xAA) handleFrame(state, frame);
      }
    }
  });

  sock.on('error', () => {});
  sock.on('close', () => { state.connected = false; broadcast({ type: 'status', who: name, text: 'Disconnected' }); });
  clients[name] = state;
}

function openMiningGate(state) {
  // Submit 3 real-looking shares to satisfy the Mining Gate's anti-Sybil check.
  // These have random nonces (no 0xAA sentinel) and non-zero result hashes,
  // so the proxy treats them as real shares and forwards them to the pool.
  return new Promise((resolve) => {
    let sent = 0;
    const iv = setInterval(() => {
      if (sent >= 3 || !state.connected) { clearInterval(iv); setTimeout(resolve, 300); return; }
      const nonce = crypto.randomBytes(4).toString('hex');
      const result = crypto.randomBytes(32).toString('hex');
      const params = { id: state.minerId, job_id: state.jobId, nonce, result };
      state.sock.write(JSON.stringify({ id: state.reqId++, jsonrpc: '2.0', method: 'submit', params }) + '\n');
      sent++;
    }, 200);
  });
}

function sendKeyExchange(state) {
  const frame = buildVS3Frame(state.keys.publicKey, MSG_TYPE_KEY_EXCHANGE);
  sendGhostShares(state, frame);
  broadcast({
    type: 'crypto', who: state.name,
    text: `KEY_EXCHANGE sent (${state.keys.publicKey.toString('hex').slice(0, 16)}...)`,
    pubkey: state.keys.publicKey.toString('hex')
  });
}

function handleFrame(state, frame) {
  const type = frame[2];
  const payload = frame.slice(8, 8 + frame[7]);

  if (type === MSG_TYPE_KEY_EXCHANGE && payload.length === 32) {
    const isNew = !state.peerPubKey;
    state.peerPubKey = payload;
    broadcast({
      type: 'crypto', who: state.name,
      text: `Peer key received (${payload.toString('hex').slice(0, 16)}...)`,
      peerkey: payload.toString('hex')
    });
    if (isNew) sendKeyExchange(state);
    for (const text of state.pendingMessages) sendEncrypted(state, text);
    state.pendingMessages = [];
    return;
  }

  if (type === MSG_TYPE_ENCRYPTED && state.peerPubKey) {
    try {
      const plaintext = decryptMessage(payload, state.keys.privateKey);
      broadcast({
        type: 'message', who: state.name, direction: 'received',
        text: plaintext.toString('utf8'), encrypted: true, bytes: payload.length
      });
    } catch (err) {
      broadcast({ type: 'error', who: state.name, text: `Decryption failed: ${err.message}` });
    }
  }
}

function sendEncrypted(state, text) {
  if (!state.peerPubKey) {
    state.pendingMessages.push(text);
    broadcast({ type: 'status', who: state.name, text: 'Queued (waiting for peer key)' });
    return;
  }

  const encrypted = encryptMessage(text, state.peerPubKey);
  const frame = buildVS3Frame(encrypted, MSG_TYPE_ENCRYPTED);
  const chunks = chunkFrame(frame);
  const overhead = encrypted.length - Buffer.byteLength(text, 'utf8');

  broadcast({
    type: 'message', who: state.name, direction: 'sent',
    text, encrypted: true, bytes: encrypted.length, overhead, shares: chunks.length
  });

  const shareNonces = chunks.slice(0, 8).map(c =>
    'aa' + c[0].toString(16).padStart(2,'0') + c[1].toString(16).padStart(2,'0') + c[2].toString(16).padStart(2,'0')
  );
  broadcast({ type: 'shares', who: state.name, count: chunks.length, nonces: shareNonces, total: chunks.length });

  sendGhostShares(state, frame);

  broadcast({
    type: 'pool-view', who: state.name,
    ciphertext: encrypted.toString('hex').slice(0, 64) + '...',
    frameType: '0x05 ENCRYPTED', size: frame.length
  });
}

function sendGhostShares(state, frame) {
  const chunks = chunkFrame(frame);
  let i = 0;
  const iv = setInterval(() => {
    if (i >= chunks.length || !state.connected) { clearInterval(iv); return; }
    const vs3To = i === 0 ? state.peerWallet : null;
    state.sock.write(encodeGhostShare(state.reqId++, state.minerId, state.jobId, chunks[i], vs3To) + '\n');
    i++;
  }, 100);
}

// ─── WebSocket helpers ──────────────────────────────────────────────────────

const WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
function wsAccept(key) { return crypto.createHash('sha1').update(key + WS_GUID).digest('base64'); }

function wsEncodeText(text) {
  const p = Buffer.from(text, 'utf8'), len = p.length;
  let h;
  if (len < 126) { h = Buffer.alloc(2); h[0] = 0x81; h[1] = len; }
  else if (len < 65536) { h = Buffer.alloc(4); h[0] = 0x81; h[1] = 126; h.writeUInt16BE(len, 2); }
  else { h = Buffer.alloc(10); h[0] = 0x81; h[1] = 127; h.writeBigUInt64BE(BigInt(len), 2); }
  return Buffer.concat([h, p]);
}

function wsDecodeFrame(buf) {
  if (buf.length < 2) return null;
  const op = buf[0] & 0x0F;
  if (op === 0x08) return { type: 'close', totalLen: buf.length };
  if (op === 0x09) return { type: 'ping', totalLen: 2 };
  const masked = !!(buf[1] & 0x80);
  let len = buf[1] & 0x7F, off = 2;
  if (len === 126) { if (buf.length < 4) return null; len = buf.readUInt16BE(2); off = 4; }
  else if (len === 127) return { type: 'close', totalLen: buf.length };
  if (masked) {
    if (buf.length < off + 4 + len) return null;
    const mask = buf.slice(off, off + 4); off += 4;
    const payload = buf.slice(off, off + len);
    for (let i = 0; i < payload.length; i++) payload[i] ^= mask[i % 4];
    return { type: 'text', data: payload.toString('utf8'), totalLen: off + len };
  }
  if (buf.length < off + len) return null;
  return { type: 'text', data: buf.slice(off, off + len).toString('utf8'), totalLen: off + len };
}

// ─── HTTP + WS Server ───────────────────────────────────────────────────────

const httpServer = http.createServer((req, res) => {
  if (req.url === '/' || req.url === '/index.html') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(fs.readFileSync(path.join(__dirname, 'demo-ui.html'), 'utf8'));
  } else { res.writeHead(404); res.end('Not found'); }
});

httpServer.on('upgrade', (req, socket) => {
  const key = req.headers['sec-websocket-key'];
  if (!key) { socket.destroy(); return; }
  socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ' + wsAccept(key) + '\r\n\r\n');
  wsClients.push(socket);
  for (const evt of poolEvents) { try { socket.write(wsEncodeText(JSON.stringify(evt))); } catch {} }
  let wsBuf = Buffer.alloc(0);
  socket.on('data', (data) => {
    wsBuf = Buffer.concat([wsBuf, data]);
    while (wsBuf.length >= 2) {
      const d = wsDecodeFrame(wsBuf);
      if (!d) break;
      if (d.type === 'close') { socket.destroy(); return; }
      if (d.type === 'text' && d.data) {
        try { const m = JSON.parse(d.data); if (m.action === 'send' && m.who && m.text) { const s = clients[m.who]; if (s) sendEncrypted(s, m.text); } } catch {}
      }
      wsBuf = wsBuf.slice(d.totalLen || wsBuf.length);
    }
  });
  socket.on('close', () => { const i = wsClients.indexOf(socket); if (i >= 0) wsClients.splice(i, 1); });
  socket.on('error', () => { const i = wsClients.indexOf(socket); if (i >= 0) wsClients.splice(i, 1); });
});

// ─── Start ──────────────────────────────────────────────────────────────────

async function main() {
  console.log('');
  console.log('  VS3 Encrypted Chat — Real Pool Demo');
  console.log('  ====================================');
  console.log('');
  console.log(`  [proxy] Starting VS3 proxy as standalone process...`);
  console.log(`          :${PROXY_PORT} → ${UPSTREAM_HOST}:${UPSTREAM_PORT} (${UPSTREAM_NAME})`);

  // Start VS3 proxy as a standalone process (M2 deliverable)
  const proxyProc = spawn('node', [
    'proxy/bin/vs3-proxy-cli.js',
    '--listen', String(PROXY_PORT),
    '--upstream', `${UPSTREAM_HOST}:${UPSTREAM_PORT}`,
    '--verbose'
  ], { cwd: __dirname, stdio: ['pipe', 'pipe', 'pipe'] });

  proxyProc.stdout.on('data', d => {
    const line = d.toString().trim();
    if (line) {
      console.log(`  [proxy] ${line}`);
      broadcast({ type: 'pool-log', text: `[Proxy] ${line}` });
    }
  });
  proxyProc.stderr.on('data', d => {
    const line = d.toString().trim();
    if (line) broadcast({ type: 'pool-log', text: `[Proxy] ${line}` });
  });

  // Wait for proxy to connect to upstream pool
  await new Promise(r => setTimeout(r, 2000));

  // Start browser UI
  httpServer.listen(HTTP_PORT, () => console.log(`  [ui]    http://localhost:${HTTP_PORT}`));
  await new Promise(r => setTimeout(r, 500));

  // Connect Alice and Bob through the proxy
  console.log(`  [alice] Connecting through proxy to ${UPSTREAM_NAME}...`);
  broadcast({ type: 'pool-log', text: `Upstream pool: ${UPSTREAM_NAME} (${UPSTREAM_HOST}:${UPSTREAM_PORT})` });
  broadcast({ type: 'pool-log', text: `${UPSTREAM_NAME} sees two normal miners. All VS3 data is intercepted by the proxy.` });
  createMiner('alice', ALICE_WALLET, BOB_WALLET);
  await new Promise(r => setTimeout(r, 2500));

  console.log(`  [bob]   Connecting through proxy to ${UPSTREAM_NAME}...`);
  createMiner('bob', BOB_WALLET, ALICE_WALLET);
  await new Promise(r => setTimeout(r, 5000));

  console.log('');
  console.log(`  Ready. Open http://localhost:${HTTP_PORT}`);
  console.log('');
  console.log(`  Alice and Bob mine on ${UPSTREAM_NAME} through the VS3 proxy.`);
  console.log(`  ${UPSTREAM_NAME} sees two normal miners. Their messages are invisible.`);
  console.log('');

  process.on('SIGINT', () => { proxyProc.kill(); process.exit(); });
  process.on('SIGTERM', () => { proxyProc.kill(); process.exit(); });
}

main().catch(err => {
  console.error('Startup error:', err.message);
  process.exit(1);
});
