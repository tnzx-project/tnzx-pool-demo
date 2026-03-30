'use strict';
/**
 * vs3-proxy.js — VS3 Middleware Proxy (Full Stack)
 *
 * Sits between any Stratum miner and any Stratum pool.
 * Implements the complete VS3 protocol stack:
 *
 *   1. Mining Gate  — PoW state machine gates VS3 access (anti-Sybil)
 *   2. V1 Channel   — 1 byte/share hidden in nonce LSB of REAL shares (steganographic)
 *   3. V3 Channel   — 5 bytes/share via ghost shares (high bandwidth)
 *   4. WebSocket     — Real-time relay after stego bootstrap
 *
 * Architecture:
 *   [Miner] ──Stratum──▶ [VS3 Proxy] ──Stratum──▶ [Any Pool]
 *   [Miner] ──WebSocket──▶ [VS3 Proxy]              (after bootstrap)
 *
 * @license LGPL-2.1
 */

const net = require('net');
const http = require('http');
const crypto = require('crypto');
const { EventEmitter } = require('events');

// ── Constants ────────────────────────────────────────────────────────────────

const GHOST_MAGIC  = 0xAA;
const GHOST_HEADER = 8;
const VERSION_V3   = 0x03;
const ZERO_RESULT  = '0'.repeat(64);
const WS_GUID      = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

// ── HMAC Ghost Tag (Appendix D) ─────────────────────────────────────────────
// Replaces fixed 0xAA sentinel with HMAC-derived per-share tag.
// Key: HKDF-SHA256(miner_pass, pool_salt, "tnzx-ghost-v1")
// Tag: HMAC-SHA256(session_key, nonce[1..3])[0]
// False positive rate: 1/256, resolved by frame header validation.

function hmacDeriveKey(minerPass, poolSalt) {
  const ikm  = Buffer.from(minerPass, 'utf8');
  const salt = Buffer.from(poolSalt, 'utf8');
  const info = Buffer.from('tnzx-ghost-v1', 'utf8');
  if (typeof crypto.hkdfSync === 'function') {
    return Buffer.from(crypto.hkdfSync('sha256', ikm, salt, info, 32));
  }
  // Fallback HKDF (Node < 20)
  const prk = crypto.createHmac('sha256', salt).update(ikm).digest();
  return crypto.createHmac('sha256', prk)
    .update(Buffer.concat([info, Buffer.from([1])]))
    .digest();
}

function hmacSentinel(sessionKey, nonceData) {
  return crypto.createHmac('sha256', sessionKey).update(nonceData).digest()[0];
}

function hmacVerify(sessionKey, nonceBuf) {
  if (!nonceBuf || nonceBuf.length < 4) return false;
  return nonceBuf[0] === hmacSentinel(sessionKey, nonceBuf.slice(1, 4));
}

// ── Mining Gate ──────────────────────────────────────────────────────────────

const GATE_INACTIVE  = 'INACTIVE';
const GATE_GRACE     = 'GRACE';
const GATE_ACTIVE    = 'ACTIVE';
const GATE_SUSPENDED = 'SUSPENDED';

class MiningGate {
  constructor(opts = {}) {
    this.gracePeriodMs      = opts.gracePeriodMs      || 120000; // 2 min
    this.cooldownMs         = opts.cooldownMs         || 300000; // 5 min
    this.minSharesActivation = opts.minSharesActivation || 3;
    this.minHashrate        = opts.minHashrate        || 10;     // H/s
    this.windowMs           = opts.windowMs           || 600000; // 10 min
    this.state       = GATE_INACTIVE;
    this.connectedAt = null;
    this.suspendedAt = null;
    this.recentShares = [];
  }

  recordShare(difficulty = 1) {
    const now = Date.now();
    this.recentShares.push({ timestamp: now, difficulty });
    // Prune old shares
    const cutoff = now - this.windowMs;
    this.recentShares = this.recentShares.filter(s => s.timestamp > cutoff);

    if (this.state === GATE_INACTIVE) {
      this.state = GATE_GRACE;
      this.connectedAt = now;
    }

    if (this.state === GATE_GRACE) {
      const graceShares = this.recentShares.filter(
        s => s.timestamp >= (this.connectedAt || 0)
      );
      if (graceShares.length >= this.minSharesActivation) {
        this.state = GATE_ACTIVE;
      }
    }

    if (this.state === GATE_SUSPENDED) {
      if (now - this.suspendedAt >= this.cooldownMs && this.getHashrate() >= this.minHashrate) {
        this.state = GATE_ACTIVE;
      }
    }
  }

  getHashrate() {
    const cutoff = Date.now() - this.windowMs;
    const recent = this.recentShares.filter(s => s.timestamp > cutoff);
    if (recent.length < 2) return recent.length > 0 ? recent[0].difficulty : 0;
    const totalDiff = recent.reduce((sum, s) => sum + s.difficulty, 0);
    const elapsed = Math.max(recent[recent.length - 1].timestamp - recent[0].timestamp, 1000);
    return Math.floor(totalDiff / (elapsed / 1000));
  }

  isOpen() { return this.state === GATE_ACTIVE; }

  getShareCount() { return this.recentShares.length; }
}

// ── WebSocket helpers (minimal, zero-dep) ────────────────────────────────────

function wsAccept(key) {
  return crypto.createHash('sha1').update(key + WS_GUID).digest('base64');
}

function wsEncodeText(text) {
  const payload = Buffer.from(text, 'utf8');
  const len = payload.length;
  let header;
  if (len < 126) {
    header = Buffer.alloc(2);
    header[0] = 0x81; // FIN + TEXT opcode
    header[1] = len;
  } else {
    header = Buffer.alloc(4);
    header[0] = 0x81;
    header[1] = 126;
    header.writeUInt16BE(len, 2);
  }
  return Buffer.concat([header, payload]);
}

function wsDecodeFrame(buf) {
  if (buf.length < 2) return null;
  const opcode = buf[0] & 0x0F;
  if (opcode === 0x08) return { type: 'close' };
  if (opcode === 0x09) return { type: 'ping' };
  const masked = !!(buf[1] & 0x80);
  let len = buf[1] & 0x7F;
  let offset = 2;
  if (len === 126) { len = buf.readUInt16BE(2); offset = 4; }
  if (masked) {
    const mask = buf.slice(offset, offset + 4); offset += 4;
    const payload = buf.slice(offset, offset + len);
    for (let i = 0; i < payload.length; i++) payload[i] ^= mask[i % 4];
    return { type: 'text', data: payload.toString('utf8'), totalLen: offset + len };
  }
  return { type: 'text', data: buf.slice(offset, offset + len).toString('utf8'), totalLen: offset + len };
}

// ── V1 extraction helper ─────────────────────────────────────────────────────

function extractV1Byte(nonceHex) {
  const buf = Buffer.from(nonceHex.padStart(8, '0'), 'hex');
  const len = buf.length;
  if (len < 2) return 0;
  return ((buf[len - 2] & 0x0F) << 4) | (buf[len - 1] & 0x0F);
}

// ══════════════════════════════════════════════════════════════════════════════
//  VS3 Proxy
// ══════════════════════════════════════════════════════════════════════════════

class VS3Proxy extends EventEmitter {
  constructor(opts = {}) {
    super();
    this.listenPort   = opts.listenPort   || 14444;
    this.wsPort       = opts.wsPort       || 14445;
    this.upstreamHost = opts.upstreamHost || '127.0.0.1';
    this.upstreamPort = opts.upstreamPort || 3333;
    this.gateOpts     = opts.gate         || {};
    this.hmacSalt     = opts.hmacSalt    || null; // null = legacy 0xAA mode
    this.server       = null;
    this.wsServer     = null;
    this.connections  = new Map();
    this.wsClients    = new Map(); // wallet → ws socket
    this.connCounter  = 0;
    this.stats = {
      ghostSharesIntercepted: 0,
      ghostSharesBlocked: 0,  // blocked by Mining Gate
      realSharesForwarded: 0,
      v1BytesExtracted: 0,
      v1Frames: 0,
      vs3Frames: 0,
      wsMessages: 0,
    };
  }

  async start() {
    // Stratum proxy
    await new Promise((resolve) => {
      this.server = net.createServer((s) => this._onMinerConnect(s));
      this.server.listen(this.listenPort, resolve);
    });
    // WebSocket relay
    await new Promise((resolve) => {
      this.wsServer = http.createServer((req, res) => {
        res.writeHead(404); res.end();
      });
      this.wsServer.on('upgrade', (req, socket, head) => this._onWsUpgrade(req, socket));
      this.wsServer.listen(this.wsPort, resolve);
    });
    this.emit('listening', { stratum: this.listenPort, ws: this.wsPort });
  }

  stop() {
    for (const [, conn] of this.connections) {
      conn.miner.destroy();
      if (conn.upstream) conn.upstream.destroy();
      if (conn.gateTimer) clearInterval(conn.gateTimer);
    }
    for (const [, ws] of this.wsClients) ws.destroy();
    this.connections.clear();
    this.wsClients.clear();
    if (this.server) this.server.close();
    if (this.wsServer) this.wsServer.close();
  }

  // ── Stratum: miner connects ──────────────────────────────────────────────

  _onMinerConnect(minerSock) {
    const connId = ++this.connCounter;
    const conn = {
      id: connId,
      miner: minerSock,
      upstream: null,
      upstreamReady: false,
      upstreamQueue: [],
      minerBuf: '',
      upstreamBuf: '',
      // Mining Gate
      gate: new MiningGate(this.gateOpts),
      gateTimer: null,
      // V3 ghost share state
      ghostBuffer: Buffer.alloc(0),
      ghostTo: null,
      ghostSharesPerMinute: 0,
      ghostRateLimitResetAt: 0,
      fragmentBuffers: new Map(),
      // V1/V2 steganographic state
      v1Buffer: Buffer.alloc(0),
      v1To: null,
      v1Active: false,
      v2Buffer: Buffer.alloc(0),
      v2To: null,
      // Download path
      pendingFrames: [],
      lastJob: null,
      wallet: null,
      minerId: null,
      // HMAC session key (derived at login if hmacSalt set)
      sessionKey: null,
      // Protocol detection (monero vs bitcoin)
      protocol: null, // 'monero' | 'bitcoin'
      extranonce2Size: 4, // bitcoin: size of extranonce2 field
    };
    this.connections.set(connId, conn);

    const upstream = net.createConnection(this.upstreamPort, this.upstreamHost, () => {
      conn.upstream = upstream;
      conn.upstreamReady = true;
      for (const q of conn.upstreamQueue) upstream.write(q + '\n');
      conn.upstreamQueue = [];
    });
    upstream.setEncoding('utf8');
    upstream.on('data', (data) => this._onUpstreamData(conn, data));
    upstream.on('error', () => this._cleanup(connId));
    upstream.on('close', () => this._cleanup(connId));

    minerSock.setEncoding('utf8');
    minerSock.on('data', (data) => this._onMinerData(conn, data));
    minerSock.on('error', () => this._cleanup(connId));
    minerSock.on('close', () => this._cleanup(connId));
  }

  _cleanup(connId) {
    const conn = this.connections.get(connId);
    if (!conn) return;
    for (const [, e] of conn.fragmentBuffers) { if (e.timer) clearTimeout(e.timer); }
    if (conn.gateTimer) clearInterval(conn.gateTimer);
    conn.miner.destroy();
    if (conn.upstream) conn.upstream.destroy();
    this.connections.delete(connId);
  }

  // ── Stratum: miner data → proxy decides ──────────────────────────────────

  _onMinerData(conn, data) {
    conn.minerBuf += data;
    const lines = conn.minerBuf.split('\n');
    conn.minerBuf = lines.pop();

    for (const line of lines) {
      if (!line.trim()) continue;
      let msg;
      try { msg = JSON.parse(line); } catch { continue; }

      // ── Protocol detection ──
      if (!conn.protocol) {
        if (msg.method === 'login') conn.protocol = 'monero';
        else if (msg.method === 'mining.subscribe' || msg.method === 'mining.authorize') conn.protocol = 'bitcoin';
      }

      // ── Monero submit ──
      if (msg.method === 'submit' && msg.params && typeof msg.params === 'object' && !Array.isArray(msg.params)) {
        this._handleMoneroSubmit(conn, msg);
        continue;
      }

      // ── Bitcoin mining.submit ── params: ["worker", "job_id", "extranonce2", "ntime", "nonce"]
      if (msg.method === 'mining.submit' && Array.isArray(msg.params) && msg.params.length >= 5) {
        this._handleBitcoinSubmit(conn, msg);
        continue;
      }

      // ── Monero login ──
      if (msg.method === 'login' && msg.params) {
        conn.wallet = msg.params.login;
        if ((msg.params.agent || '').includes('vs3')) conn.v1Active = true;
        // HMAC key derivation (Appendix D)
        if (this.hmacSalt && msg.params.pass) {
          conn.sessionKey = hmacDeriveKey(msg.params.pass, this.hmacSalt);
        }
        // Sanitize agent string before forwarding to upstream pool
        const sanitized = { ...msg, params: { ...msg.params, agent: 'XMRig/6.21.0' } };
        this._sendToUpstream(conn, JSON.stringify(sanitized));
        continue;  // Don't forward the original line
      }

      // ── Bitcoin authorize ── params: ["worker.name", "password"]
      if (msg.method === 'mining.authorize' && Array.isArray(msg.params)) {
        conn.wallet = msg.params[0];
        conn.v1Active = true; // V1/V2 always active on Bitcoin
        // HMAC key derivation (Appendix D)
        if (this.hmacSalt && msg.params[1]) {
          conn.sessionKey = hmacDeriveKey(msg.params[1], this.hmacSalt);
        }
      }

      this._sendToUpstream(conn, line);
    }
  }

  // ── Stratum: upstream data → proxy may inject VS3 ────────────────────────

  // ── Monero submit handler ──────────────────────────────────────────────

  _handleMoneroSubmit(conn, msg) {
    const nonce  = (msg.params.nonce || '').toLowerCase();
    const result = (msg.params.result || '').toLowerCase();

    // Ghost share detection: HMAC mode or legacy 0xAA sentinel
    const nonceBuf = Buffer.from(nonce.padStart(8, '0'), 'hex');
    const isGhost = conn.sessionKey
      ? (hmacVerify(conn.sessionKey, nonceBuf) && result === ZERO_RESULT)
      : (nonce.startsWith('aa') && result === ZERO_RESULT);
    if (isGhost) {
      if (!conn.gate.isOpen()) {
        this.stats.ghostSharesBlocked++;
        this._sendToMiner(conn, { id: msg.id, result: { status: 'OK' } });
        return;
      }
      this.stats.ghostSharesIntercepted++;
      this._handleGhostShare(conn, msg.params);
      this._sendToMiner(conn, { id: msg.id, result: { status: 'OK' } });
      return;
    }

    // Real share — forward + Mining Gate + V1 extract
    this.stats.realSharesForwarded++;
    conn.gate.recordShare(1);
    if (conn.v1Active || conn.gate.isOpen()) {
      this._extractV1(conn, nonce);
    }
    this._checkGateOpen(conn);
    this._sendToUpstream(conn, JSON.stringify(msg));
  }

  // ── Bitcoin submit handler ───────────────────────────────────────────────
  // params: ["worker", "job_id", "extranonce2", "ntime", "nonce"]

  _handleBitcoinSubmit(conn, msg) {
    const [worker, jobId, extranonce2, ntime, nonce] = msg.params;
    const nonceLower = (nonce || '').toLowerCase();
    const en2Lower   = (extranonce2 || '').toLowerCase();

    // Ghost share detection: HMAC mode or legacy 0xAA sentinel
    const nonceBuf = Buffer.from(nonceLower.padStart(8, '0'), 'hex');
    const isGhost = conn.sessionKey
      ? hmacVerify(conn.sessionKey, nonceBuf)
      : (nonceLower.startsWith('aa') && en2Lower.startsWith('aa'));
    if (isGhost) {
      if (!conn.gate.isOpen()) {
        this.stats.ghostSharesBlocked++;
        this._sendToMiner(conn, { id: msg.id, result: true, error: null });
        return;
      }
      this.stats.ghostSharesIntercepted++;
      // V3-Standard: 7 bytes/share — nonce[1..3](3B) + extranonce2[1..](up to 3B) + ntime[2..3](2B)
      this._handleBitcoinGhostShare(conn, nonceLower, en2Lower, (ntime || '').toLowerCase());
      this._sendToMiner(conn, { id: msg.id, result: true, error: null });
      return;
    }

    // Real share — forward + Mining Gate + V1/V2 extract
    this.stats.realSharesForwarded++;
    conn.gate.recordShare(1);

    if (conn.v1Active || conn.gate.isOpen()) {
      // V1: 1 byte from nonce LSB
      this._extractV1(conn, nonceLower);
      // V2: +2 bytes from extranonce2 last 2 bytes (3 total per share)
      this._extractV2(conn, nonceLower, en2Lower);
    }
    this._checkGateOpen(conn);
    this._sendToUpstream(conn, JSON.stringify(msg));
  }

  _handleBitcoinGhostShare(conn, nonce, extranonce2, ntime) {
    // V3-Standard: extract 7 payload bytes
    const nb = Buffer.from(nonce.padStart(8, '0'), 'hex');
    const eb = Buffer.from(extranonce2.padStart(8, '0'), 'hex');
    const tb = Buffer.from(ntime.padStart(8, '0'), 'hex');
    // nonce[1..3] = 3 bytes, extranonce2[1..3] = up to 3 bytes, ntime[2..3] = 2 bytes
    const payload = Buffer.concat([
      nb.slice(1, 4),           // 3 bytes from nonce
      eb.slice(1, Math.min(4, eb.length)),  // up to 3 bytes from extranonce2
      tb.slice(2, 4),           // 2 bytes from ntime
    ]);
    // Use vs3_to from extranonce2 metadata (not available in positional params)
    // For now, ghost routing uses same mechanism as Monero
    conn.ghostBuffer = Buffer.concat([conn.ghostBuffer, payload]);
    if (conn.ghostBuffer.length > 4096) { conn.ghostBuffer = Buffer.alloc(0); return; }
    this._parseFrames(conn, 'ghostBuffer', 'ghostTo', 'vs3');
  }

  // ── V1/V2 extraction helpers ─────────────────────────────────────────────

  _extractV1(conn, nonce) {
    const v1byte = extractV1Byte(nonce);
    conn.v1Buffer = Buffer.concat([conn.v1Buffer, Buffer.from([v1byte])]);
    this.stats.v1BytesExtracted++;
    if (conn.v1Buffer.length > 4096) conn.v1Buffer = Buffer.alloc(0);
    this._parseV1Frames(conn);
  }

  _extractV2(conn, nonce, extranonce2) {
    // V2: 3 bytes total — nonce LSB (1B) + extranonce2 last 2 bytes (2B)
    const v1byte = extractV1Byte(nonce);
    const ebuf = Buffer.from(extranonce2.padStart(8, '0'), 'hex');
    const elen = ebuf.length;
    const e1 = elen >= 2 ? ebuf[elen - 2] : 0;
    const e2 = elen >= 2 ? ebuf[elen - 1] : 0;
    conn.v2Buffer = Buffer.concat([conn.v2Buffer, Buffer.from([v1byte, e1, e2])]);
    this.stats.v2BytesExtracted = (this.stats.v2BytesExtracted || 0) + 3;
    if (conn.v2Buffer.length > 4096) conn.v2Buffer = Buffer.alloc(0);
    this._parseFrames(conn, 'v2Buffer', 'v2To', 'v2');
  }

  _checkGateOpen(conn) {
    if (conn.gate.state === GATE_ACTIVE && !conn._gateWasOpen) {
      conn._gateWasOpen = true;
      this.emit('gate-open', { wallet: conn.wallet, connId: conn.id, shares: conn.gate.getShareCount() });
    }
  }

  // ── Stratum: upstream data → proxy may inject VS3 ────────────────────────

  _onUpstreamData(conn, data) {
    conn.upstreamBuf += data;
    const lines = conn.upstreamBuf.split('\n');
    conn.upstreamBuf = lines.pop();

    for (const line of lines) {
      if (!line.trim()) continue;
      let msg;
      try { msg = JSON.parse(line); } catch {
        this._sendRawToMiner(conn, line + '\n');
        continue;
      }

      // ── Monero: login response with job ──
      if (msg.result && msg.result.id && msg.result.job) {
        conn.minerId = msg.result.id;
        conn.lastJob = { method: 'job', params: msg.result.job };
      }

      // ── Bitcoin: mining.subscribe response → capture extranonce2_size ──
      if (msg.id && Array.isArray(msg.result) && msg.result.length >= 2) {
        // result: [[[mining.set_difficulty, ...], [mining.notify, ...]], extranonce1, extranonce2_size]
        if (typeof msg.result[msg.result.length - 1] === 'number') {
          conn.extranonce2Size = msg.result[msg.result.length - 1];
        }
      }

      // ── Monero: job notification ──
      if (msg.method === 'job' && msg.params) {
        conn.lastJob = { method: msg.method, params: { ...msg.params } };
        if (conn.pendingFrames.length > 0) {
          msg.params.vs3 = conn.pendingFrames.shift().toString('hex');
        }
      }

      // ── Bitcoin: mining.notify → save as last job ──
      if (msg.method === 'mining.notify' && Array.isArray(msg.params)) {
        conn.lastJob = { method: msg.method, params: [...msg.params] };
      }

      this._sendToMiner(conn, msg);
    }
  }

  // ── V3 Ghost Shares (5 bytes/share) ──────────────────────────────────────

  _handleGhostShare(conn, params) {
    const now = Date.now();
    if (now >= conn.ghostRateLimitResetAt) {
      conn.ghostSharesPerMinute = 0;
      conn.ghostRateLimitResetAt = now + 60000;
    }
    if (++conn.ghostSharesPerMinute > 120) return;

    const nb = Buffer.from((params.nonce || '').padStart(8, '0'), 'hex');
    const tb = Buffer.from((params.ntime || '').padStart(8, '0'), 'hex');
    const payload = Buffer.concat([nb.slice(1, 4), tb.slice(2, 4)]);

    if (typeof params.vs3_to === 'string' && params.vs3_to.length >= 10) {
      conn.ghostTo = params.vs3_to;
    }

    conn.ghostBuffer = Buffer.concat([conn.ghostBuffer, payload]);
    if (conn.ghostBuffer.length > 4096) { conn.ghostBuffer = Buffer.alloc(0); return; }
    this._parseFrames(conn, 'ghostBuffer', 'ghostTo', 'vs3');
  }

  // ── V1 Steganographic Channel (1 byte/share from real shares) ────────────

  _parseV1Frames(conn) {
    this._parseFrames(conn, 'v1Buffer', 'v1To', 'v1');
  }

  // ── Generic frame parser (works for both V1 and V3 buffers) ──────────────

  _parseFrames(conn, bufKey, toKey, channel) {
    const knownTypes = [0x01, 0x02, 0x03, 0x04, 0x05];

    while (conn[bufKey].length >= GHOST_HEADER) {
      if (conn[bufKey][0] !== GHOST_MAGIC) {
        conn[bufKey] = conn[bufKey].slice(1);
        continue;
      }
      const ver  = conn[bufKey][1];
      const type = conn[bufKey][2];
      if (ver !== VERSION_V3 || !knownTypes.includes(type)) {
        conn[bufKey] = conn[bufKey].slice(1);
        continue;
      }
      const frameSize = GHOST_HEADER + conn[bufKey][7];
      if (frameSize < GHOST_HEADER || frameSize > GHOST_HEADER + 255) {
        conn[bufKey] = conn[bufKey].slice(1);
        continue;
      }
      if (conn[bufKey].length < frameSize) break;

      const frame = conn[bufKey].slice(0, frameSize);
      conn[bufKey] = conn[bufKey].slice(frameSize);

      if (channel === 'v1') this.stats.v1Frames++;
      else this.stats.vs3Frames++;

      const fragTotal = frame[6];
      const fragPayload = frame.slice(8, 8 + frame[7]);

      if (fragTotal === 1) {
        const evt = {
          from: conn.wallet, to: conn[toKey], frame, channel,
          text: fragPayload.toString('utf8'), connId: conn.id,
        };
        this.emit('vs3-frame', evt);
        if (conn[toKey]) {
          this.deliverFrame(conn[toKey], frame);
          this._deliverToWs(conn[toKey], evt);
        }
        conn[toKey] = null;
      } else {
        this._handleFragment(conn, frame, toKey, channel);
      }
    }
  }

  _handleFragment(conn, frame, toKey, channel) {
    const msgId     = (frame[3] << 8) | frame[4];
    const fragIndex = frame[5];
    const fragTotal = frame[6];
    const fragPayload = frame.slice(8, 8 + frame[7]);

    if (!conn.fragmentBuffers.has(msgId)) {
      const timer = setTimeout(() => conn.fragmentBuffers.delete(msgId), 30000);
      conn.fragmentBuffers.set(msgId, {
        fragments: new Array(fragTotal).fill(null),
        received: 0, total: fragTotal,
        header: frame.slice(0, 8), timer, to: conn[toKey],
      });
    }
    const entry = conn.fragmentBuffers.get(msgId);
    if (entry && entry.fragments[fragIndex] === null) {
      entry.fragments[fragIndex] = fragPayload;
      if (++entry.received === entry.total) {
        clearTimeout(entry.timer);
        conn.fragmentBuffers.delete(msgId);
        const full = Buffer.concat(entry.fragments);
        const reassembled = Buffer.alloc(GHOST_HEADER + full.length);
        entry.header.copy(reassembled, 0);
        reassembled[5] = 0; reassembled[6] = 1; reassembled[7] = full.length;
        full.copy(reassembled, GHOST_HEADER);
        if (channel === 'v1') this.stats.v1Frames++;
        else this.stats.vs3Frames++;
        const evt = {
          from: conn.wallet, to: entry.to, frame: reassembled, channel,
          text: full.toString('utf8'), connId: conn.id,
        };
        this.emit('vs3-frame', evt);
        if (entry.to) {
          this.deliverFrame(entry.to, reassembled);
          this._deliverToWs(entry.to, evt);
        }
        conn[toKey] = null;
      }
    }
  }

  // ── Download path: deliver frame to miner ────────────────────────────────

  deliverFrame(recipientWallet, frame) {
    for (const [, conn] of this.connections) {
      if (conn.wallet === recipientWallet) {
        conn.pendingFrames.push(frame);
        if (conn.lastJob) {
          const jobMsg = JSON.parse(JSON.stringify(conn.lastJob));
          jobMsg.params.vs3 = conn.pendingFrames.shift().toString('hex');
          this._sendToMiner(conn, jobMsg);
        }
        return true;
      }
    }
    return false;
  }

  // ── WebSocket relay ──────────────────────────────────────────────────────

  _onWsUpgrade(req, socket) {
    const key = req.headers['sec-websocket-key'];
    if (!key) { socket.destroy(); return; }

    socket.write(
      'HTTP/1.1 101 Switching Protocols\r\n' +
      'Upgrade: websocket\r\n' +
      'Connection: Upgrade\r\n' +
      'Sec-WebSocket-Accept: ' + wsAccept(key) + '\r\n\r\n'
    );

    let wsBuf = Buffer.alloc(0);
    let wallet = null;

    socket.on('data', (data) => {
      wsBuf = Buffer.concat([wsBuf, data]);
      while (wsBuf.length >= 2) {
        const decoded = wsDecodeFrame(wsBuf);
        if (!decoded) break;
        if (decoded.type === 'close') { socket.destroy(); return; }
        if (decoded.type === 'ping') {
          // Send pong
          const pong = Buffer.alloc(2); pong[0] = 0x8A; pong[1] = 0;
          socket.write(pong);
          wsBuf = wsBuf.slice(decoded.totalLen || 2);
          continue;
        }
        if (decoded.type === 'text' && decoded.data) {
          try {
            const msg = JSON.parse(decoded.data);
            if (msg.type === 'auth' && msg.wallet) {
              // Authenticate: must have an active Mining Gate via Stratum
              wallet = msg.wallet;
              const hasActiveGate = this._hasActiveGate(wallet);
              this.wsClients.set(wallet, socket);
              socket.write(wsEncodeText(JSON.stringify({
                type: 'auth', ok: hasActiveGate,
                reason: hasActiveGate ? 'Mining Gate active' : 'Mining Gate not active — mine first',
              })));
            } else if (msg.type === 'msg' && msg.to && msg.text && wallet) {
              if (!this._hasActiveGate(wallet)) continue;
              this.stats.wsMessages++;
              this.emit('ws-message', { from: wallet, to: msg.to, text: msg.text });
              this._deliverToWs(msg.to, { from: wallet, text: msg.text });
            }
          } catch {}
          wsBuf = wsBuf.slice(decoded.totalLen || wsBuf.length);
        } else break;
      }
    });

    socket.on('close', () => { if (wallet) this.wsClients.delete(wallet); });
    socket.on('error', () => { if (wallet) this.wsClients.delete(wallet); });
  }

  _hasActiveGate(wallet) {
    for (const [, conn] of this.connections) {
      if (conn.wallet === wallet && conn.gate.isOpen()) return true;
    }
    return false;
  }

  _deliverToWs(recipientWallet, evt) {
    const ws = this.wsClients.get(recipientWallet);
    if (ws && !ws.destroyed) {
      ws.write(wsEncodeText(JSON.stringify({
        type: 'msg', from: evt.from, text: evt.text, channel: evt.channel || 'ws',
      })));
    }
  }

  // ── Transport helpers ────────────────────────────────────────────────────

  _sendToMiner(conn, obj) {
    try { conn.miner.write(JSON.stringify(obj) + '\n'); } catch {}
  }

  _sendRawToMiner(conn, data) {
    try { conn.miner.write(data); } catch {}
  }

  _sendToUpstream(conn, line) {
    if (conn.upstreamReady && conn.upstream && !conn.upstream.destroyed) {
      try { conn.upstream.write(line + '\n'); } catch {}
    } else {
      conn.upstreamQueue.push(line);
    }
  }
}

module.exports = VS3Proxy;
