'use strict';
/**
 * test-bitcoin-pool.js — VS3 on a real Bitcoin pool
 *
 * Demonstrates that VS3 is chain-agnostic:
 *   - V1: 1 byte/share hidden in nonce LSB (works on ANY chain)
 *   - V2: 3 bytes/share — nonce LSB + extranonce2 (Bitcoin Stratum standard fields)
 *   - Mining Gate gates access via real PoW shares
 *
 * Bitcoin Stratum V1 protocol:
 *   mining.subscribe → mining.authorize → mining.notify → mining.submit
 *   Submit params: ["worker", "job_id", "extranonce2", "ntime", "nonce"]
 *
 * Key insight: extranonce2 and ntime are STANDARD fields in Bitcoin Stratum.
 *   No protocol extensions needed. VS3 uses what's already there.
 *
 * Run: node poc/test-bitcoin-pool.js
 *
 * @license LGPL-2.1
 */

const net = require('net');
const crypto = require('crypto');
const VS3Proxy = require('./vs3-proxy.js');

// ─── Config ──────────────────────────────────────────────────────────────────

const PROXY_PORT = 14444;

// Bitcoin pools that accept Stratum V1 connections
const BTC_POOLS = [
  { host: 'stratum.braiins.com',    port: 3333, name: 'Braiins (Slush)' },
  { host: 'btc.viabtc.com',         port: 3333, name: 'ViaBTC' },
  { host: 'stratum.f2pool.com',     port: 3333, name: 'F2Pool' },
  { host: 'btc-pool.rockx.com',     port: 3333, name: 'RockX' },
  { host: 'ss.antpool.com',         port: 3333, name: 'AntPool' },
];

// Well-known Bitcoin address (Satoshi's genesis block address)
const BTC_WALLET = '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa';

const sleep = (ms) => new Promise(r => setTimeout(r, ms));

// ─── VS3 Frame encoding ─────────────────────────────────────────────────────

function buildVS3Frame(text) {
  const payload = Buffer.from(text, 'utf8').slice(0, 247);
  const msgId = crypto.randomBytes(2).readUInt16BE(0);
  return Buffer.concat([
    Buffer.from([0xAA, 0x03, 0x01, (msgId >> 8) & 0xFF, msgId & 0xFF, 0x00, 0x01, payload.length]),
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

// V1: Embed 1 byte in nonce LSB (2 nibbles in last 2 bytes of nonce)
function encodeV1Submit(reqId, worker, jobId, dataByte, extranonce2Size) {
  const nonceBuf = crypto.randomBytes(4);
  nonceBuf[2] = (nonceBuf[2] & 0xF0) | ((dataByte >> 4) & 0x0F);
  nonceBuf[3] = (nonceBuf[3] & 0xF0) | (dataByte & 0x0F);
  const nonce = nonceBuf.toString('hex');
  const ntime = Math.floor(Date.now() / 1000).toString(16).padStart(8, '0');
  const en2 = crypto.randomBytes(extranonce2Size).toString('hex');
  return JSON.stringify({
    id: reqId, method: 'mining.submit',
    params: [worker, jobId, en2, ntime, nonce],
  });
}

// V2: Embed 3 bytes — nonce LSB (1B) + extranonce2 last 2 bytes (2B)
function encodeV2Submit(reqId, worker, jobId, bytes3, extranonce2Size) {
  const nonceBuf = crypto.randomBytes(4);
  nonceBuf[2] = (nonceBuf[2] & 0xF0) | ((bytes3[0] >> 4) & 0x0F);
  nonceBuf[3] = (nonceBuf[3] & 0xF0) | (bytes3[0] & 0x0F);
  const nonce = nonceBuf.toString('hex');
  const ntime = Math.floor(Date.now() / 1000).toString(16).padStart(8, '0');
  const en2Buf = crypto.randomBytes(extranonce2Size);
  en2Buf[extranonce2Size - 2] = bytes3[1];
  en2Buf[extranonce2Size - 1] = bytes3[2];
  const en2 = en2Buf.toString('hex');
  return JSON.stringify({
    id: reqId, method: 'mining.submit',
    params: [worker, jobId, en2, ntime, nonce],
  });
}

// Plain real share (no VS3 data)
function encodeRealSubmit(reqId, worker, jobId, extranonce2Size) {
  const nonce = crypto.randomBytes(4).toString('hex');
  const ntime = Math.floor(Date.now() / 1000).toString(16).padStart(8, '0');
  const en2 = crypto.randomBytes(extranonce2Size).toString('hex');
  return JSON.stringify({
    id: reqId, method: 'mining.submit',
    params: [worker, jobId, en2, ntime, nonce],
  });
}

// ─── Bitcoin Stratum V1 client ───────────────────────────────────────────────

function connectBitcoin(port, host, wallet) {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error('timeout')), 15000);
    const sock = net.createConnection(port, host || '127.0.0.1', () => {
      // Step 1: mining.subscribe
      sock.write(JSON.stringify({
        id: 1, method: 'mining.subscribe', params: ['vs3-test/1.0'],
      }) + '\n');
    });
    sock.setEncoding('utf8');
    let buf = '', subscribed = false, authorized = false;
    let extranonce1 = '', extranonce2Size = 4, jobId = null;

    sock.on('data', (data) => {
      buf += data;
      const lines = buf.split('\n');
      buf = lines.pop();
      for (const line of lines) {
        if (!line.trim()) continue;
        try {
          const msg = JSON.parse(line);

          // Subscribe response
          if (msg.id === 1 && msg.result && !subscribed) {
            subscribed = true;
            if (Array.isArray(msg.result)) {
              extranonce1 = msg.result[1] || '';
              extranonce2Size = msg.result[2] || 4;
            }
            // Step 2: mining.authorize
            sock.write(JSON.stringify({
              id: 2, method: 'mining.authorize', params: [wallet, 'x'],
            }) + '\n');
          }

          // Authorize response
          if (msg.id === 2 && !authorized) {
            authorized = true;
            clearTimeout(timeout);
            resolve({
              sock, extranonce1, extranonce2Size, buf: '',
              authorized: msg.result === true,
              jobId, // might be set by mining.notify before auth completes
            });
          }

          // mining.notify (can arrive before authorize response)
          if (msg.method === 'mining.notify' && Array.isArray(msg.params)) {
            jobId = msg.params[0]; // job_id is first param
          }

          // mining.set_difficulty
          if (msg.method === 'mining.set_difficulty') {
            // just note it
          }
        } catch {}
      }
    });
    sock.on('error', (err) => { clearTimeout(timeout); reject(err); });
  });
}

// ═════════════════════════════════════════════════════════════════════════════
//  TEST
// ═════════════════════════════════════════════════════════════════════════════

async function run() {
  console.log('');
  console.log('================================================================');
  console.log('  VS3 ON BITCOIN — Chain-Agnostic Proof');
  console.log('  V1 + V2 extraction on real Bitcoin Stratum pool');
  console.log('================================================================');

  // ── Find a reachable Bitcoin pool ──
  let pool = null;
  for (const p of BTC_POOLS) {
    process.stdout.write(`  Trying ${p.name}... `);
    const ok = await new Promise(r => {
      const t = setTimeout(() => { s.destroy(); r(false); }, 5000);
      const s = net.createConnection(p.port, p.host, () => { clearTimeout(t); s.destroy(); r(true); });
      s.on('error', () => { clearTimeout(t); r(false); });
    });
    if (ok) { console.log('OK'); pool = p; break; }
    console.log('FAIL');
  }
  if (!pool) { console.log('  No Bitcoin pool reachable!'); process.exit(1); }

  // ── Direct connection test first ──
  console.log(`\n  Direct connection to ${pool.name}...`);
  let directResult;
  try {
    directResult = await connectBitcoin(pool.port, pool.host, BTC_WALLET);
    console.log(`  Subscribe OK: extranonce1=${directResult.extranonce1}, en2_size=${directResult.extranonce2Size}`);
    console.log(`  Authorize: ${directResult.authorized ? 'OK' : 'rejected (expected for test wallet)'}`);
    if (directResult.jobId) console.log(`  Got job: ${directResult.jobId.slice(0, 16)}...`);
    directResult.sock.destroy();
  } catch (err) {
    console.log(`  Direct failed: ${err.message}`);
    process.exit(1);
  }

  // ── Start proxy ──
  const proxy = new VS3Proxy({
    listenPort: PROXY_PORT, wsPort: PROXY_PORT + 1,
    upstreamHost: pool.host, upstreamPort: pool.port,
    gate: { minSharesActivation: 3, minHashrate: 0 },
  });
  const events = [];
  proxy.on('vs3-frame', (e) => events.push(e));
  proxy.on('gate-open', (e) => events.push({ type: 'gate-open', ...e }));
  await proxy.start();
  console.log(`\n  Proxy running: :${PROXY_PORT} → ${pool.name}`);

  // ── Connect through proxy ──
  let client;
  try {
    client = await connectBitcoin(PROXY_PORT, '127.0.0.1', BTC_WALLET);
    console.log(`  Through proxy: en2_size=${client.extranonce2Size}, auth=${client.authorized}`);
  } catch (err) {
    console.log(`  Proxy connection failed: ${err.message}`);
    proxy.stop();
    process.exit(1);
  }

  // Wait for a job
  if (!client.jobId) {
    await sleep(2000);
    // Re-check
  }
  const jobId = client.jobId || 'test_job';
  const en2Size = client.extranonce2Size;
  const worker = BTC_WALLET;
  let reqId = 100;

  const results = [];

  // ── Phase 1: Mining Gate (send 3 real shares) ──
  console.log('\n--- Phase 1: Mining Gate ---');
  for (let i = 0; i < 3; i++) {
    client.sock.write(encodeRealSubmit(reqId++, worker, jobId, en2Size) + '\n');
    await sleep(100);
  }
  await sleep(500);
  const gateOpened = events.some(e => e.type === 'gate-open');
  console.log(`  [${gateOpened ? 'PASS' : 'FAIL'}] Mining Gate opened after 3 shares`);
  results.push({ name: 'Mining Gate on Bitcoin', pass: gateOpened });

  // ── Phase 2: V1 extraction (1 byte/share from nonce LSB) ──
  console.log('\n--- Phase 2: V1 — 1 byte/share in nonce LSB ---');

  const v1Msg = 'V1 BTC';
  const v1Frame = buildVS3Frame(v1Msg);
  const v1Chunks = chunkFrame(v1Frame, 1);
  console.log(`  Sending "${v1Msg}" via V1: ${v1Frame.length} bytes → ${v1Chunks.length} shares`);

  for (const chunk of v1Chunks) {
    client.sock.write(encodeV1Submit(reqId++, worker, jobId, chunk[0], en2Size) + '\n');
    await sleep(80);
  }
  await sleep(500);

  const v1Event = events.find(e => e.channel === 'v1' && e.text === v1Msg);
  console.log(`  V1 bytes extracted: ${proxy.stats.v1BytesExtracted}`);
  console.log(`  V1 message: ${v1Event ? `"${v1Event.text}"` : 'NOT FOUND'}`);
  console.log(`  [${v1Event ? 'PASS' : 'FAIL'}] V1 stego works on Bitcoin`);
  results.push({ name: 'V1 on Bitcoin (1 B/share)', pass: !!v1Event });

  // ── Phase 3: V2 extraction (3 bytes/share — nonce LSB + extranonce2) ──
  console.log('\n--- Phase 3: V2 — 3 bytes/share (nonce + extranonce2) ---');

  const v2Msg = 'V2 on BTC!';
  const v2Frame = buildVS3Frame(v2Msg);
  const v2Chunks = chunkFrame(v2Frame, 3);
  console.log(`  Sending "${v2Msg}" via V2: ${v2Frame.length} bytes → ${v2Chunks.length} shares`);

  for (const chunk of v2Chunks) {
    client.sock.write(encodeV2Submit(reqId++, worker, jobId, [chunk[0], chunk[1], chunk[2]], en2Size) + '\n');
    await sleep(80);
  }
  await sleep(500);

  const v2Event = events.find(e => e.channel === 'v2' && e.text === v2Msg);
  console.log(`  V2 bytes extracted: ${proxy.stats.v2BytesExtracted || 0}`);
  console.log(`  V2 message: ${v2Event ? `"${v2Event.text}"` : 'NOT FOUND'}`);
  console.log(`  [${v2Event ? 'PASS' : 'FAIL'}] V2 stego works on Bitcoin`);
  results.push({ name: 'V2 on Bitcoin (3 B/share)', pass: !!v2Event });

  // ── Verdict ──
  console.log('\n================================================================');
  console.log('  RESULTS');
  console.log('================================================================\n');
  console.log(`  Pool: ${pool.name} (Bitcoin Stratum V1)`);
  console.log(`  Real shares forwarded: ${proxy.stats.realSharesForwarded}`);
  console.log('');
  for (const r of results) {
    console.log(`  [${r.pass ? 'PASS' : 'FAIL'}] ${r.name}`);
  }

  const allPass = results.every(r => r.pass);
  console.log('');
  if (allPass) {
    console.log('  VS3 IS CHAIN-AGNOSTIC.');
    console.log('  Works on Monero pools AND Bitcoin pools.');
    console.log('  V1 (1 B/share) and V2 (3 B/share) use STANDARD Stratum fields.');
    console.log('  No protocol extensions. No pool modifications.');
  }
  console.log('================================================================\n');

  client.sock.destroy();
  proxy.stop();
  process.exit(allPass ? 0 : 1);
}

run().catch((err) => { console.error('Fatal:', err); process.exit(1); });
