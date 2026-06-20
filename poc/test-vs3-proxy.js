'use strict';
/**
 * test-vs3-proxy.js — End-to-end proof that VS3 proxy works with any pool
 *
 * What this test proves:
 *   1. A standard Stratum pool receives ZERO ghost shares (all filtered by proxy)
 *   2. Real shares pass through to the pool untouched
 *   3. The VS3 proxy extracts and assembles the hidden message correctly
 *   4. The upstream pool has NO VS3 code, NO modifications, NO awareness
 *
 * What this test does NOT prove:
 *   - Concurrent multi-miner frame assembly (single connection only)
 *   - Lost/reordered ghost shares mid-transmission
 *   - Proxy behavior under real network latency or packet fragmentation
 *   - PoW validation of real shares (mock pool accepts all shares)
 *   - HMAC sentinel mode (tested in test-hmac-sentinel.js, this uses legacy 0xAA)
 *   - Multi-fragment messages (test message fits in a single VS3 frame)
 *   - WebSocket relay path (tested only in test-full-stack.js against real pools)
 *
 * Run: node poc/test-vs3-proxy.js
 *
 * @license LGPL-2.1
 */

const net = require('net');
const VS3Proxy = require('./vs3-proxy.js');

// ─── Config ──────────────────────────────────────────────────────────────────
// Ports are configurable via env vars or CLI args to avoid EADDRINUSE on systems
// where the default ports are already bound (e.g., CI runners, developer machines
// running a local pool). If the requested port is busy, the test automatically
// binds to an ephemeral port (port 0 → OS-assigned).

/**
 * Try to listen on `preferred`; if EADDRINUSE, fall back to port 0 (OS picks a free one).
 * Returns the actual port the server is listening on.
 */
function listenOrFallback(server, preferred) {
  return new Promise((resolve, reject) => {
    server.once('error', (err) => {
      if (err.code === 'EADDRINUSE') {
        // Preferred port busy — let the OS assign a free one
        server.listen(0, () => resolve(server.address().port));
      } else {
        reject(err);
      }
    });
    server.listen(preferred, () => resolve(server.address().port));
  });
}

// Default ports chosen to avoid common services. Override with env vars or CLI args.
const PREFERRED_POOL_PORT  = parseInt(process.env.TEST_POOL_PORT  || process.argv[2] || '0', 10);
const PREFERRED_PROXY_PORT = parseInt(process.env.TEST_PROXY_PORT || process.argv[3] || '0', 10);
const SENDER_WALLET  = '4' + '2'.repeat(94);
const RECIP_WALLET   = '4' + '1'.repeat(94);
const TEST_MESSAGE   = 'Hello from VS3 proxy!';

// ─── Mock Standard Pool (knows NOTHING about VS3) ────────────────────────────

class MockPool {
  constructor(port) {
    this.port = port;
    this.server = null;
    this.submitsReceived = [];    // ALL submits logged verbatim
    this.ghostSharesSeen = 0;     // should be 0 if proxy works
    this.realSharesSeen = 0;
    this.miners = new Map();
  }

  start() {
    this.server = net.createServer((sock) => this._onConnect(sock));
    return listenOrFallback(this.server, this.port).then((actualPort) => {
      this.port = actualPort;
    });
  }

  stop() { if (this.server) this.server.close(); }

  _onConnect(sock) {
    let buf = '';
    sock.setEncoding('utf8');
    sock.on('data', (data) => {
      buf += data;
      const lines = buf.split('\n');
      buf = lines.pop();
      for (const line of lines) {
        if (!line.trim()) continue;
        let msg;
        try { msg = JSON.parse(line); } catch { continue; }
        this._handle(sock, msg);
      }
    });
    sock.on('error', () => {});
  }

  _handle(sock, msg) {
    if (msg.method === 'login') {
      const minerId = 'miner_' + Math.random().toString(36).slice(2, 8);
      const job = this._makeJob();
      const resp = { id: msg.id, jsonrpc: '2.0', result: { id: minerId, job, status: 'OK' } };
      sock.write(JSON.stringify(resp) + '\n');
      this.miners.set(sock, { id: minerId, job });
      return;
    }

    if (msg.method === 'submit') {
      const nonce  = (msg.params?.nonce || '').toLowerCase();
      const result = (msg.params?.result || '').toLowerCase();
      // Log every submit we receive
      this.submitsReceived.push({ nonce, result, hasNtime: !!msg.params?.ntime });

      // Check if this looks like a ghost share (it should NEVER reach us)
      if (nonce.startsWith('aa') && result === '0'.repeat(64)) {
        this.ghostSharesSeen++;
      } else {
        this.realSharesSeen++;
      }
      sock.write(JSON.stringify({ id: msg.id, result: { status: 'OK' } }) + '\n');
      return;
    }

    if (msg.method === 'keepalived') {
      sock.write(JSON.stringify({ id: msg.id, result: { status: 'KEEPALIVED' } }) + '\n');
    }
  }

  _makeJob() {
    return {
      blob: 'a'.repeat(152),
      job_id: 'job_' + Math.random().toString(36).slice(2, 8),
      target: 'b4b40000',
      height: 3000000,
      seed_hash: 'c'.repeat(64),
    };
  }
}

// ─── VS3 Frame Encoding (same as vs3-client.js) ─────────────────────────────

function buildVS3Frame(text) {
  const payload = Buffer.from(text, 'utf8').slice(0, 247);
  // Generate random 16-bit message_id (matches ref-impl generateMessageId behavior)
  const msgId = Math.floor(Math.random() * 0xFFFF);
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

function encodeRealShare(reqId, minerId, jobId) {
  const nonce = Math.floor(Math.random() * 0xFFFFFFFF).toString(16).padStart(8, '0');
  // Non-zero result = looks like a real share with valid PoW
  const result = 'deadbeef'.repeat(8);
  const params = { id: minerId, job_id: jobId, nonce, result };
  return JSON.stringify({ id: reqId, jsonrpc: '2.0', method: 'submit', params });
}

// ─── Test Runner ─────────────────────────────────────────────────────────────

async function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

/**
 * Start the VS3Proxy with EADDRINUSE fallback on both Stratum and WS ports.
 * Replaces proxy.start() which crashes on busy ports.
 *
 * @param {VS3Proxy} proxy - The proxy instance (not yet started)
 * @param {number} preferredStratumPort - Preferred Stratum port (0 = OS picks)
 * @param {number} preferredWsPort - Preferred WS port (0 = OS picks)
 */
async function _startProxyWithFallback(proxy, preferredStratumPort, preferredWsPort) {
  // Periodic cleanup of stale rate limit entries
  proxy._rateLimitCleanup = setInterval(() => {
    const now = Date.now();
    for (const [ip, entry] of proxy.ghostRateByIp) {
      if (now >= entry.resetAt) proxy.ghostRateByIp.delete(ip);
    }
  }, 120000);

  // Stratum proxy — fallback-aware
  proxy.server = net.createServer((s) => proxy._onMinerConnect(s));
  proxy.listenPort = await listenOrFallback(proxy.server, preferredStratumPort);

  // WebSocket relay — fallback-aware
  const http = require('http');
  proxy.wsServer = http.createServer((req, res) => { res.writeHead(404); res.end(); });
  proxy.wsServer.on('upgrade', (req, socket) => proxy._onWsUpgrade(req, socket));
  proxy.wsPort = await listenOrFallback(proxy.wsServer, preferredWsPort);

  proxy.emit('listening', { stratum: proxy.listenPort, ws: proxy.wsPort });
}

async function run() {
  console.log('');
  console.log('================================================================');
  console.log('  VS3 MIDDLEWARE PROXY — PROOF OF CONCEPT');
  console.log('  "Any pool becomes VS3-aware. Zero modifications."');
  console.log('================================================================');
  console.log('');

  // ── Step 1: Start mock pool ──
  const pool = new MockPool(PREFERRED_POOL_PORT);
  await pool.start();
  const actualPoolPort = pool.port;
  console.log(`[1] Mock standard pool listening on :${actualPoolPort}` +
    (actualPoolPort !== PREFERRED_POOL_PORT ? ` (fallback from :${PREFERRED_POOL_PORT})` : ''));

  // ── Step 2: Start VS3 proxy ──
  // The proxy itself also uses listenOrFallback for its Stratum and WS ports.
  // We pass the actual pool port as upstream (it may differ from the preferred one).
  // Note: _startProxyWithFallback overrides the listen ports with actual bound
  // ports, so the values passed to the constructor are only preferred hints.
  // VS3Proxy constructor treats 0 as falsy (defaults to 14444), so we pass
  // PREFERRED_PROXY_PORT directly only if non-zero.
  const proxy = new VS3Proxy({
    listenPort: PREFERRED_PROXY_PORT || 14444,
    wsPort: (PREFERRED_PROXY_PORT || 14444) + 1,
    upstreamHost: '127.0.0.1',
    upstreamPort: actualPoolPort,
    hmacSalt: false, // legacy 0xAA mode for this test (HMAC tested in test-hmac-sentinel.js)
  });

  let assembledMessage = null;
  proxy.on('vs3-frame', (evt) => {
    assembledMessage = evt;
  });

  // Override proxy.start() to use fallback-aware binding.
  // Pass the raw preferred ports (may be 0 for ephemeral).
  await _startProxyWithFallback(proxy, PREFERRED_PROXY_PORT, PREFERRED_PROXY_PORT ? PREFERRED_PROXY_PORT + 1 : 0);
  const actualProxyPort = proxy.listenPort;
  console.log(`[2] VS3 proxy listening on :${actualProxyPort} -> upstream :${actualPoolPort}` +
    (actualProxyPort !== PREFERRED_PROXY_PORT ? ` (fallback from :${PREFERRED_PROXY_PORT})` : ''));

  // ── Step 3: Connect VS3 miner to proxy ──
  const client = await new Promise((resolve, reject) => {
    const sock = net.createConnection(actualProxyPort, '127.0.0.1', () => resolve(sock));
    sock.on('error', reject);
  });
  client.setEncoding('utf8');

  // Collect responses
  const responses = [];
  let loginResolve;
  const loginPromise = new Promise(r => { loginResolve = r; });
  let clientBuf = '';
  client.on('data', (data) => {
    clientBuf += data;
    const lines = clientBuf.split('\n');
    clientBuf = lines.pop();
    for (const line of lines) {
      if (!line.trim()) continue;
      try {
        const msg = JSON.parse(line);
        responses.push(msg);
        if (msg.result && msg.result.id) loginResolve(msg);
      } catch {}
    }
  });

  // Login
  const loginMsg = JSON.stringify({
    id: 1, jsonrpc: '2.0', method: 'login',
    params: { login: SENDER_WALLET, pass: 'x', agent: 'vs3-test/1.0' },
  });
  client.write(loginMsg + '\n');
  const loginResp = await loginPromise;
  const minerId = loginResp.result.id;
  const jobId = loginResp.result.job.job_id;
  console.log(`[3] VS3 miner connected, minerId=${minerId}`);

  // ── Step 4: Send real shares to activate Mining Gate (need 3) ──
  console.log('');
  console.log('[4] Sending 3 REAL shares (activate Mining Gate + reach upstream pool)...');
  client.write(encodeRealShare(10, minerId, jobId) + '\n');
  await sleep(50);
  client.write(encodeRealShare(11, minerId, jobId) + '\n');
  await sleep(50);
  client.write(encodeRealShare(12, minerId, jobId) + '\n');
  await sleep(100);

  // ── Step 5: Send ghost shares with VS3 message ──
  const frame = buildVS3Frame(TEST_MESSAGE);
  const chunks = chunkFrame(frame);
  console.log(`[5] Sending VS3 message: "${TEST_MESSAGE}"`);
  console.log(`    Frame: ${frame.length} bytes -> ${chunks.length} ghost shares (5 B each)`);
  console.log('');

  let reqId = 100;
  for (let i = 0; i < chunks.length; i++) {
    const vs3To = i === 0 ? RECIP_WALLET : null;
    const shareJson = encodeGhostShare(reqId++, minerId, jobId, chunks[i], vs3To);
    const parsed = JSON.parse(shareJson);
    const tag = i === 0 ? ' (+ vs3_to)' : '';
    console.log(`    Share ${i + 1}/${chunks.length}: nonce=${parsed.params.nonce}${tag}`);
    client.write(shareJson + '\n');
    await sleep(100); // pace shares like a real miner
  }

  // ── Step 6: Wait for assembly ──
  await sleep(500);

  // ── Step 7: Results ──
  console.log('');
  console.log('================================================================');
  console.log('  RESULTS');
  console.log('================================================================');
  console.log('');

  // Proxy results
  console.log('  VS3 PROXY:');
  console.log(`    Ghost shares intercepted: ${proxy.stats.ghostSharesIntercepted}`);
  console.log(`    Real shares forwarded:    ${proxy.stats.realSharesForwarded}`);
  console.log(`    VS3 frames assembled:     ${proxy.stats.vs3Frames}`);
  if (assembledMessage) {
    console.log(`    Message content:          "${assembledMessage.text}"`);
    console.log(`    From: ${assembledMessage.from?.slice(0, 16)}...`);
    console.log(`    To:   ${assembledMessage.to?.slice(0, 16)}...`);
  } else {
    console.log('    Message: NOT ASSEMBLED (FAIL)');
  }
  console.log('');

  // Upstream pool results
  console.log('  UPSTREAM POOL (mock):');
  console.log(`    Total submits received:   ${pool.submitsReceived.length}`);
  console.log(`    Real shares received:     ${pool.realSharesSeen}`);
  console.log(`    Ghost shares received:    ${pool.ghostSharesSeen}`);
  if (pool.submitsReceived.length > 0) {
    console.log('    Submits log:');
    for (const s of pool.submitsReceived) {
      const type = s.nonce.startsWith('aa') ? 'GHOST (LEAKED!)' : 'real';
      console.log(`      nonce=${s.nonce} type=${type}`);
    }
  }
  console.log('');

  // ── Verdict ──
  const messageCorrect = assembledMessage && assembledMessage.text === TEST_MESSAGE;
  const noGhostLeak = pool.ghostSharesSeen === 0;
  const realSharesOk = pool.realSharesSeen === 3;
  const allPass = messageCorrect && noGhostLeak && realSharesOk;

  console.log('  CHECKS:');
  console.log(`    [${messageCorrect ? 'PASS' : 'FAIL'}] VS3 message assembled correctly`);
  console.log(`    [${noGhostLeak ? 'PASS' : 'FAIL'}] Zero ghost shares leaked to upstream pool`);
  console.log(`    [${realSharesOk ? 'PASS' : 'FAIL'}] Real shares forwarded to pool (expected 3, got ${pool.realSharesSeen})`);
  console.log('');
  console.log('================================================================');
  if (allPass) {
    console.log('  VERDICT: ALL TESTS PASSED');
    console.log('');
    console.log('  The upstream pool received ZERO VS3 data.');
    console.log('  The proxy extracted the message transparently.');
    console.log('  No pool modification required. Any Stratum pool works.');
  } else {
    console.log('  VERDICT: SOME TESTS FAILED');
  }
  console.log('================================================================');
  console.log('');

  // Cleanup
  client.destroy();
  proxy.stop();
  pool.stop();
  process.exit(allPass ? 0 : 1);
}

run().catch((err) => {
  console.error('Test error:', err);
  process.exit(1);
});
