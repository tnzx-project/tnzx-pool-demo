'use strict';
/**
 * ============================================================================
 * TNZX VS3 Protocol — Reference Implementation
 * Stratum server with VS3 encapsulated "ghost share" support.
 * ============================================================================
 *
 * CONTEXT & MOTIVATION
 * --------------------
 * In high-censorship environments (authoritarian states, corporate networks
 * with Deep Packet Inspection), standard secure-messaging channels (Signal,
 * Tor, VPNs) are either blocked outright or fingerprinted at the network
 * layer. Even traffic that is nominally encrypted can be identified and
 * throttled based on flow characteristics (packet timing, handshake patterns,
 * SNI leakage, port reputation).
 *
 * TNZX VS3 ("Vector Data Encapsulation v3") embeds arbitrary messages inside
 * standard Monero cryptocurrency mining (Stratum) traffic.
 *
 * WHY MONERO STRATUM?
 * -------------------
 *   1. CPU-mineable: Monero uses RandomX, so any laptop or server can mine
 *      without specialized hardware. No ASIC required to participate.
 *
 *   2. TLS in production: real pool connections run over TLS. This demo
 *      uses plaintext TCP for readability; adding TLS is one layer up.
 *
 *   3. Structural freedom in share fields: the Stratum protocol requires
 *      miners to submit nonce and ntime values, but pools cannot validate
 *      them against a known-correct answer before accepting a share. These
 *      fields carry payload bytes without breaking protocol compliance.
 *
 *   4. Ghost shares are structurally identical to low-difficulty real shares:
 *      same JSON object shape, same field names, same "OK" response.
 *
 * WHAT THIS FILE DEMONSTRATES
 * ---------------------------
 *   1. A complete, minimal XMRig-compatible Stratum server (login / submit /
 *      job dispatch) — the baseline "normal" mining server behavior.
 *   2. Ghost shares: Stratum submit messages that carry hidden VS3 payload
 *      bytes in their nonce and ntime fields (upload path: miner → pool).
 *   3. VS3 frame reassembly: the pool reconstructs full VS3 frames from the
 *      byte stream delivered across multiple ghost shares.
 *   4. Reverse delivery: the pool injects VS3 frames into outgoing job
 *      notifications (download path: pool → miner).
 *   5. Zero protocol modification: a network observer sees standard Stratum
 *      JSON throughout. No new methods, no structural anomalies.
 *
 * OPEN PROTOCOL
 * -------------
 * VS3 is specified in the public tnzx-protocol repository. Any pool or
 * client can implement it independently. No proprietary relay, no central
 * authority.
 *
 * ============================================================================
 * VS3 GHOST SHARE — STEGANOGRAPHIC ENCODING (UPLOAD PATH)
 * ============================================================================
 *
 * Each Stratum "submit" message carries two fields we exploit:
 *
 *   {
 *     "method": "submit",
 *     "params": {
 *       "nonce": "aabbccdd",   // 4 bytes, hex — freely chosen by the miner
 *       "ntime": "65f3a200",   // 4 bytes, hex — Unix timestamp (low 32 bits)
 *       ...
 *     }
 *   }
 *
 * ENCODING LAYOUT (5 secret bytes per ghost share):
 *
 *   nonce byte [0]   = 0xAA  ← sentinel: marks this submit as a ghost share
 *   nonce byte [1]   = payload[0]  ┐
 *   nonce byte [2]   = payload[1]  │ 3 bytes of VS3 payload in nonce
 *   nonce byte [3]   = payload[2]  ┘
 *   ntime byte [0]   = (Unix_epoch >> 24) & 0xFF  ┐ real timestamp high word
 *   ntime byte [1]   = (Unix_epoch >> 16) & 0xFF  ┘ keeps ntime plausible
 *   ntime byte [2]   = payload[3]  ┐ 2 bytes of VS3 payload in ntime low word
 *   ntime byte [3]   = payload[4]  ┘
 *
 * WHY THESE SPECIFIC FIELDS?
 *   nonce: the Stratum specification explicitly states the miner may choose
 *     any 4-byte nonce when submitting. The pool cannot reject a share based
 *     on nonce value — only on proof-of-work difficulty. The 0xAA sentinel
 *     in byte [0] is our ghost-share marker; it is also a valid nonce byte.
 *
 *   ntime: pools accept ntime within a ±7200-second window of real time
 *     (NTP drift tolerance). We preserve the high 16 bits of the real Unix
 *     epoch so the value stays within this window, and overwrite only the
 *     low 16 bits with payload data. The low bits contribute at most ~18
 *     hours of drift, well inside the acceptance window.
 *
 *   5 bytes/share: this is the maximum extractable from these two fields
 *     without touching any other Stratum field. At a ghost share rate of
 *     1 Hz (easily achieved even on low-power hardware), throughput is
 *     ~5 bytes/s ≈ 300 bytes/min — sufficient for text messaging and
 *     compressed metadata (e.g. a Signal key bundle is ~200 bytes).
 *
 * GHOST SHARE DETECTION (pool side):
 *   The pool flags a submit as a ghost share if and only if:
 *     (a) nonce starts with "aa"  (0xAA sentinel byte), AND
 *     (b) miner.difficulty <= GHOST_DIFF_MAX
 *   Condition (b) eliminates the 1/256 chance of a real high-difficulty
 *   share starting with 0xAA. Real shares at high difficulty are never
 *   misrouted; they fall through to normal share processing.
 *
 * ============================================================================
 * VS3 FRAME FORMAT
 * ============================================================================
 *
 *  Byte  Field           Size   Description
 *  ────  ──────────────  ────   ──────────────────────────────────────────────
 *  [0]   MAGIC           1      Always 0xAA — frame boundary marker
 *  [1]   version         1      Protocol version (current: 0x03 = VS3)
 *  [2]   type            1      0x01=text, 0x02=ack, 0x03=ping (MSG_TYPE in stego-core)
 *  [3-4] message_id      2      Unique ID for this logical message (big-endian)
 *  [5]   fragment_index  1      Which fragment this is (0-based)
 *  [6]   fragment_total  1      Total fragments in this message (1 = no split)
 *  [7]   payload_len     1      N: byte length of payload in this frame (0-255)
 *  [8..8+N] payload      N      Message content (UTF-8 text or binary)
 *
 *  Minimum frame: GHOST_HEADER = 8 bytes (empty payload, N=0)
 *  Maximum frame: 8 + 255 = 263 bytes → spans ceil(263/5) = 53 ghost shares
 *
 *  NUMERICAL EXAMPLE — sending "Hello" (5 bytes) as a single fragment:
 *
 *  Index:  0    1    2    3    4    5    6    7    8    9   10   11   12
 *  Hex:   AA   03   01   00   01   00   01   05   48   65   6C   6C   6F
 *         ↑    ↑    ↑    ↑────↑    ↑    ↑    ↑    ↑────────────────────
 *         │    │    │    msg_id    │    │    │    payload = "Hello"
 *         │    │    type=text      │    │    payload_len = 5
 *         │    version=3           │    fragment_total = 1
 *         MAGIC (sentinel)         fragment_index = 0
 *
 *  This 13-byte frame is split across ceil(13/5) = 3 ghost shares:
 *    Share 1 nonce/ntime → bytes [AA 03 01 00 01]  (sentinel + first 4 bytes)
 *    Share 2 nonce/ntime → bytes [00 01 05 48 65]
 *    Share 3 nonce/ntime → bytes [6C 6C 6F -- --]  (last 3, two slots unused)
 *
 * Note: this demo logs VS3 frame payloads to stdout for readability.
 * Encryption (X25519 + XChaCha20-Poly1305, HKDF-SHA256) is a separate layer
 * not included here — the transport is intentionally kept minimal so the
 * encapsulated mechanism can be audited without cryptographic tooling.
 *
 * @license LGPL-2.1
 */

const net   = require('net');
const http  = require('http');
const EventEmitter = require('events');
const crypto = require('crypto');

// ── Config ─────────────────────────────────────────────────────────────────
//
// All parameters are injectable via environment variables, enabling this demo
// to run against any Monero daemon (mainnet, stagenet, or a local regtest
// node) without code changes.
//
const CFG = {
  stratumPort : parseInt(process.env.STRATUM_PORT  || '4444'),
  apiPort     : parseInt(process.env.API_PORT      || '8090'),
  daemonHost  : process.env.DAEMON_HOST || '127.0.0.1',
  daemonPort  : parseInt(process.env.DAEMON_PORT   || '38081'),
  daemonUser  : process.env.DAEMON_USER || '',
  daemonPass  : process.env.DAEMON_PASS || '',
  // poolAddress: in production this is the operator's Monero wallet address.
  // The placeholder '4' + '0'*94 is syntactically valid (correct length and
  // prefix for a Monero mainnet address) but unspendable — safe for demos
  // and CI runs that do not involve a real wallet.
  poolAddress : process.env.POOL_ADDRESS || '4' + '0'.repeat(94),
  // ghostDiffMax: shares submitted at difficulty <= this value are eligible
  // for ghost share detection. Ghost shares are intentionally assigned very
  // low target difficulty (effectively difficulty 1) so the sender can submit
  // them rapidly without expending meaningful computational work. A real miner
  // submitting at high difficulty will never be misidentified as a ghost
  // sender even if a nonce coincidentally starts with 0xAA.
  // Default 500: low enough to never conflict with real mining sessions, which
  // operate at difficulty 100,000+. Override via GHOST_DIFF_MAX env var if needed.
  ghostDiffMax: parseInt(process.env.GHOST_DIFF_MAX || '500'),
  // Mining Gate parameters — configurable for different PoW profiles.
  // See protocols/vs2/MINING-GATE.md for semantics.
  gateWindowMs     : parseInt(process.env.GATE_WINDOW_MS     || '600000'),  // 10 min
  gateThreshold    : parseFloat(process.env.GATE_THRESHOLD   || '0.5'),     // 50% of expected share rate
  gateGraceMs      : parseInt(process.env.GATE_GRACE_MS      || '120000'),  // 2 min
  gateCooldownMs   : parseInt(process.env.GATE_COOLDOWN_MS   || '300000'),  // 5 min
  gateMinShares    : parseInt(process.env.GATE_MIN_SHARES    || '3'),
  gateMinHashrate  : parseInt(process.env.GATE_MIN_HASHRATE  || '10'),      // H/s
};

// ── Daemon RPC ──────────────────────────────────────────────────────────────
//
// Minimal wrapper around the Monero daemon's JSON-RPC 2.0 interface.
// Used exclusively to fetch the current block template, which supplies the
// mining blob and RandomX seed hash that clients need to construct valid
// proof-of-work candidates.
//
// In a production pool this would also handle block submission when a miner
// solves the puzzle. For this demo, block submission is omitted because the
// VS3 transport mechanism is entirely independent of whether shares represent
// real solved blocks.
//
function daemonRPC(method, params = []) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({ jsonrpc:'2.0', id:'0', method, params });
    const headers = { 'Content-Type':'application/json', 'Content-Length': Buffer.byteLength(body) };
    // HTTP Basic auth is optional. Monero daemons can be configured to
    // require credentials even for local RPC connections as defense-in-depth.
    if (CFG.daemonUser) headers['Authorization'] = 'Basic ' + Buffer.from(`${CFG.daemonUser}:${CFG.daemonPass}`).toString('base64');
    const req = http.request({
      host: CFG.daemonHost, port: CFG.daemonPort,
      path: '/json_rpc', method: 'POST', headers
    }, res => {
      let d = ''; res.on('data', c => d += c);
      res.on('end', () => { try { resolve(JSON.parse(d)); } catch(e) { reject(e); } });
    });
    req.on('error', reject);
    req.write(body); req.end();
  });
}

// ── VS3 Ghost Share constants ───────────────────────────────────────────────
//
// GHOST_MAGIC (0xAA): the sentinel byte that serves double duty —
//   (1) it is the first byte of every VS3 frame (frame boundary marker), AND
//   (2) it is the first byte of every ghost share's nonce field, acting as a
//       cheap O(1) filter before the pool commits to parsing the payload.
//
// GHOST_HEADER (8): byte length of a VS3 frame header. The pool must
// accumulate at least this many bytes before it can determine the total frame
// length (GHOST_HEADER + frame[7]). Partial frames are held in the per-miner
// ghost buffer until their remaining bytes arrive in subsequent shares.
//
const GHOST_MAGIC  = 0xAA;
const GHOST_HEADER = 8;
// FIX: SPEC-02 — current VS3 protocol version byte constant.
// Versions 0x04/0x05/0x06 (BURST/GHOST/TURBO) are known future versions
// not yet supported by this server; they are logged and gracefully skipped.
const VERSION_V3   = 0x03; // FIX: SPEC-02

// ── Stratum Server ──────────────────────────────────────────────────────────
//
// StratumDemo is a minimal but complete XMRig-compatible Stratum server.
// It handles the three message types that constitute the entire Stratum
// mining lifecycle: login (session handshake), submit (share delivery), and
// job dispatch (pool-initiated work assignment).
//
// Inheriting from EventEmitter cleanly separates transport from application
// logic: higher-level components subscribe to "vs3-frame" events and handle
// decryption, routing, and UI delivery without coupling to Stratum internals.
//
class StratumDemo extends EventEmitter {
  constructor() {
    super();
    // miners: Map<sessionId, minerState> — all currently connected TCP clients.
    this.miners   = new Map();
    // jobs: Map<jobId, jobObject> — enables share validation (not used in this
    // demo but present for protocol completeness and future extension).
    this.jobs     = new Map();
    // stats: live counters exposed via the HTTP monitoring API.
    this.stats    = { connected: 0, ghostShares: 0, vs3Frames: 0 };
    this.blockTemplate = null;
  }

  start() {
    // Fetch block template immediately so the first miner to connect receives
    // a valid job without waiting up to 30 seconds for the polling interval.
    this._fetchBlockTemplate();
    // Poll the daemon every 30 seconds. In production this would be replaced
    // by the daemon's long-poll endpoint (/json_rpc with "getblocktemplate"
    // and a blocking wait), which delivers the new template within milliseconds
    // of a block being found. Polling is used here to keep the demo self-
    // contained and easy to audit.
    setInterval(() => this._fetchBlockTemplate(), 30000);

    net.createServer(sock => this._handleMiner(sock))
      .listen(CFG.stratumPort, () =>
        console.log(`[VS3-Demo] Stratum listening on :${CFG.stratumPort}`));
  }

  async _fetchBlockTemplate() {
    try {
      const r = await daemonRPC('getblocktemplate', {
        wallet_address: CFG.poolAddress, reserve_size: 8
      });
      if (r.result) {
        this.blockTemplate = r.result;
        // Immediately push new jobs to all authorized miners. This matches
        // standard pool behavior: when the chain advances, all miners must
        // switch to the new block to avoid wasting hash power on a stale tip.
        for (const [,m] of this.miners) if (m.authorized) this._sendJob(m);
        console.log(`[VS3-Demo] Block template updated, height=${r.result.height}`);
      }
    } catch(e) {
      // Daemon may be temporarily unreachable (restart, sync, network blip).
      // The pool continues operating with the last known template — miners
      // stay connected and keep submitting shares (including ghost shares)
      // until connectivity is restored.
      console.warn(`[VS3-Demo] Daemon unreachable: ${e.message}`);
    }
  }

  _handleMiner(sock) {
    // Cryptographically random session ID: no sequential or predictable
    // identifier that could leak connection-order metadata.
    const id = crypto.randomBytes(8).toString('hex');
    const miner = {
      id, sock, authorized: false, wallet: null,
      // Initial difficulty mirrors CFG.ghostDiffMax so the ghost share detection
      // threshold in _submit() stays consistent with the configured value.
      // In this demo the server always assigns difficulty 1 (target ffffffff);
      // the <= ghostDiffMax check exists only to exclude high-difficulty real miners.
      difficulty: CFG.ghostDiffMax,
      // ghostBuffer: a sliding byte queue that accumulates VS3 payload bytes
      // extracted from consecutive ghost shares. Frames are parsed and removed
      // from the front as soon as they are complete; partial frame tails remain
      // until their bytes arrive in subsequent shares.
      ghostBuffer: Buffer.alloc(0),
      // Rate limiting: cap ghost share ingestion at 120/minute per connection.
      // The counter resets every 60 seconds. Excess shares are silently dropped
      // (no disconnect) so legitimate burst patterns do not break the session.
      ghostSharesPerMinute: 0,
      ghostRateLimitResetAt: Date.now() + 60000
    };
    this.miners.set(id, miner);
    this.stats.connected++;
    // Stratum uses newline-delimited JSON over a persistent TCP connection.
    // We buffer partial lines to handle TCP segment fragmentation correctly.
    let buf = '';

    sock.on('data', d => {
      buf += d.toString();
      // FIX: SEC-03 — if buf exceeds 64 KB without newline, close the connection
      // and log the event. Protects against malicious clients sending data without \n.
      if (buf.length > 65536) {
        console.warn(`[VS3-Demo] Buffer overflow (>${65536}B without newline) from miner ${id} — connection closed`); // FIX: SEC-03
        sock.destroy();
        return;
      }
      // split('\n') gives complete lines plus an incomplete tail (kept in buf).
      const lines = buf.split('\n'); buf = lines.pop();
      for (const line of lines) {
        if (!line.trim()) continue;
        // Silently discard malformed JSON. Real miners emit occasional
        // keepalive newlines and may send incomplete frames during reconnect.
        try { this._handleMsg(miner, JSON.parse(line)); } catch(_) {}
      }
    });
    sock.on('close', () => { this.miners.delete(id); this.stats.connected--; });
    // 'error' always precedes 'close'; suppress to avoid unhandled-error crash.
    sock.on('error', () => {});
  }

  _handleMsg(miner, msg) {
    // Standard Stratum method dispatch. These three methods cover 100% of
    // normal XMRig client behavior. No protocol extensions are required on
    // the client side to use VS3 ghost shares — the "submit" method is
    // already the correct vehicle for ghost share delivery.
    const { id, method, params } = msg;
    if (method === 'login')      return this._login(miner, id, params);
    if (method === 'submit')     return this._submit(miner, id, params);
    if (method === 'keepalived') return this._send(miner, { id, result: 'KEEPALIVED' });
  }

  _login(miner, id, params) {
    // params.login is the miner's Monero wallet address. In VS3, this doubles
    // as the sender's identity for message routing — no separate registration,
    // account creation, or identity system is required.

    // FIX: SEC-01 — validate wallet address before authorizing the session.
    // Valid Monero addresses: string, length 95-106 chars, starts with '4' or '8'.
    const wallet = params.login;
    if (
      typeof wallet !== 'string' ||
      wallet.length < 95 ||
      wallet.length > 106 ||
      (wallet[0] !== '4' && wallet[0] !== '8')
    ) {
      this._send(miner, { id, error: { code: -1, message: 'Invalid wallet address' } }); // FIX: SEC-01 error response
      miner.sock.destroy(); // FIX: SEC-01 close the connection
      console.warn(`[VS3-Demo] Login rejected (invalid wallet): ${String(wallet).slice(0,20)}`);
      return;
    }

    miner.wallet     = wallet;
    miner.authorized = true;
    const job = this._makeJob(miner);
    // The login response follows the XMRig Stratum spec exactly:
    //   { id: <session_id>, job: <first_job>, status: "OK" }
    // A network observer sees a standard pool handshake, indistinguishable
    // from any other XMRig-compatible pool.
    this._send(miner, { id, result: { id: miner.id, job, status: 'OK' } });
    console.log(`[VS3-Demo] Miner login: ${miner.wallet?.slice(0,16)}...`);
  }

  _submit(miner, id, params) {
    const nonce = (params.nonce || '').toLowerCase();

    // ── Ghost share detection ──────────────────────────────────────────────
    //
    // Two conditions must both be true for a submit to be treated as a ghost
    // share rather than a real share:
    //
    //   (a) nonce starts with "aa": the 0xAA sentinel byte is present in
    //       nonce[0], signaling that nonce[1..3] and ntime[2..3] carry VS3
    //       payload bytes rather than a genuine proof-of-work nonce.
    //
    //   (b) miner.difficulty <= ghostDiffMax: ensures we only interpret low-
    //       difficulty submits as ghost shares. A real miner solving a high-
    //       difficulty share has a 1/256 chance of producing a nonce starting
    //       with 0xAA; this condition prevents misrouting that share.
    //
    // The response ("OK") is identical for both code paths, so a passive
    // observer cannot distinguish ghost share acknowledgment from a real
    // accepted share.
    //
    // VS3-Generic profile (extranonce2-based encoding, 7 bytes/share) is outside
    // the scope of this demo, which targets the VS3-Monero profile only.
    // See protocols/vs3/README.md for the Generic profile specification.
    if (nonce.startsWith('aa') && miner.difficulty <= CFG.ghostDiffMax) {
      this.stats.ghostShares++;
      this._handleGhostShare(miner, params);
      this._send(miner, { id, result: { status: 'OK' } });
      return;
    }

    // ── Normal share ───────────────────────────────────────────────────────
    // In a production pool this would verify proof-of-work and credit the
    // miner's account. Omitted here to keep the demo focused on VS3 transport.
    this._send(miner, { id, result: { status: 'OK' } });
  }

  _handleGhostShare(miner, params) {
    // Rate-limit enforcement. The counter was already incremented by _submit();
    // if over the per-minute cap, drop this share silently without disconnecting.
    const now = Date.now();
    if (now >= miner.ghostRateLimitResetAt) {
      miner.ghostSharesPerMinute = 0;
      miner.ghostRateLimitResetAt = now + 60000;
    }
    miner.ghostSharesPerMinute++;
    if (miner.ghostSharesPerMinute > 120) {
      return; // FIX: SEC-02 silently ignore beyond rate limit
    }

    // ── Step 1: Extract the 5 hidden payload bytes ─────────────────────────
    //
    // nonce field decoding:
    //   Input:  "aa4865c3"  (8 hex chars = 4 bytes)
    //   Parsed: [0xAA, 0x48, 0x65, 0xC3]
    //   Payload from nonce: nb[1..3] = [0x48, 0x65, 0xC3]  (3 bytes)
    //
    // ntime field decoding:
    //   Input:  "65f36c6f"  (8 hex chars = 4 bytes)
    //   Parsed: [0x65, 0xF3, 0x6C, 0x6F]
    //   tb[0..1] = [0x65, 0xF3] = real Unix epoch >> 16 (timestamp plausibility)
    //   Payload from ntime: tb[2..3] = [0x6C, 0x6F]  (2 bytes)
    //
    // Combined 5-byte payload for this share: [0x48, 0x65, 0xC3, 0x6C, 0x6F]
    //
    const nb = Buffer.from((params.nonce || '').padStart(8,'0'), 'hex');
    const tb = Buffer.from((params.ntime || '').padStart(8,'0'), 'hex');
    const payload = Buffer.concat([nb.slice(1,4), tb.slice(2,4)]); // 5 bytes

    // ── Step 2: Capture the destination address (first share only) ─────────
    //
    // The sender includes a "vs3_to" field in the params of the first ghost
    // share of each message, specifying the recipient's Monero wallet address.
    // This is a Stratum extension field: XMRig passes through unrecognized
    // params fields transparently, so no client modification is needed beyond
    // populating this one extra key. Pools that do not implement VS3 ignore it.
    //
    // vs3_to is only present in the first share of a message. Capture it locally
    // here and persist it on the miner object so it remains available across all
    // subsequent shares that make up the same frame.
    const shareGhostTo = (typeof params.vs3_to === 'string' && params.vs3_to.length >= 95)
      ? params.vs3_to : null;
    // Persist routing target across shares: vs3_to is only in the first share but the
    // frame assembles across many shares. Save it so it's available at emit time.
    if (shareGhostTo) miner.ghostTo = shareGhostTo;

    // ── Step 3: Append payload bytes to the per-miner stream buffer ─────────
    //
    // Multiple consecutive ghost shares contribute bytes to the same VS3
    // frame. TCP guarantees in-order delivery, so the concatenation preserves
    // byte order across shares. The buffer grows until a complete frame
    // (header + payload_len bytes) is present.
    //
    miner.ghostBuffer = Buffer.concat([miner.ghostBuffer, payload]);
    // Overflow guard: if a sender aborts mid-frame and the buffer exceeds 4 KB
    // without yielding a valid parseable frame, we reset it. This caps memory
    // usage per miner and prevents a trivial DoS via malformed ghost shares.
    if (miner.ghostBuffer.length > 4096) miner.ghostBuffer = Buffer.alloc(0); // overflow guard

    // ── Step 4: Greedily parse complete VS3 frames from the buffer ──────────
    //
    // We loop because a single ghost share may complete more than one frame
    // (e.g. if a previous share delivered the final bytes of frame N and the
    // first bytes of frame N+1). Each iteration either consumes one complete
    // frame or breaks to wait for more bytes.
    //
    // Parse complete VS3 frames
    while (miner.ghostBuffer.length >= GHOST_HEADER) {
      // Re-synchronization: if the buffer head is not the magic byte, we have
      // misalignment (e.g. post-overflow, or a dropped share created a gap).
      // Advance one byte at a time until we land on a valid frame start.
      // Note: 0xAA can appear as a legitimate payload byte, so we validate
      // the full MAGIC+VERSION+TYPE triple before treating a byte as a frame header.
      if (miner.ghostBuffer[0] !== GHOST_MAGIC) {
        miner.ghostBuffer = miner.ghostBuffer.slice(1); continue;
      }
      const ver  = miner.ghostBuffer[1];
      const type = miner.ghostBuffer[2];
      // MSG_TYPE enum per VS3 spec: TEXT=0x01, ACK=0x02, PING=0x03,
      // KEY_EXCHANGE=0x04, MSG_ENCRYPTED=0x05, HASHCASH=0x06.
      const knownTypes = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
      if (ver === 0x04 || ver === 0x05 || ver === 0x06) {
        // Reserved version bytes for future protocol extensions. Log and skip.
        console.warn(`[VS3] Unsupported version 0x${ver.toString(16).padStart(2,'0')} — upgrade required`);
        miner.ghostBuffer = miner.ghostBuffer.slice(1); continue;
      }
      if (ver !== VERSION_V3 || !knownTypes.includes(type)) {
        // Unknown version or type: treat as false 0xAA in payload, skip.
        miner.ghostBuffer = miner.ghostBuffer.slice(1); continue;
      }
      // frame[7] = payload_len (N). Total frame size in bytes = 8 + N.
      const frameSize = GHOST_HEADER + miner.ghostBuffer[7];
      // Reject impossible frame sizes (payload_len must fit in one byte: 0–255).
      if (frameSize < GHOST_HEADER || frameSize > GHOST_HEADER + 255) {
        miner.ghostBuffer = miner.ghostBuffer.slice(1); continue;
      }
      // Incomplete frame: the payload bytes have not arrived yet. Hold the
      // buffer and wait for the next ghost share to deliver more bytes.
      if (miner.ghostBuffer.length < frameSize) break;

      // Consume the complete frame from the front of the buffer.
      const frame = miner.ghostBuffer.slice(0, frameSize);
      miner.ghostBuffer = miner.ghostBuffer.slice(frameSize);
      this.stats.vs3Frames++;

      // FIX: SPEC-04 — Fragment reassembly for multi-fragment messages.
      // frame[3..4] = message_id (big-endian), frame[5] = fragment_index,
      // frame[6] = fragment_total. If fragment_total === 1, emit immediately.
      // Otherwise accumulate in miner.fragmentBuffers (Map<message_id, ...>)
      // with a 30-second timeout for incomplete fragments.
      const msgId         = (frame[3] << 8) | frame[4];
      const fragIndex     = frame[5];
      const fragTotal     = frame[6];
      const fragPayload   = frame.slice(8, 8 + frame[7]);

      if (fragTotal === 1) {
        // Single-fragment message: emit immediately.
        // FIX: BUG-04 — use miner.ghostTo (persisted from the first share's vs3_to).
        // For multi-fragment, miner.ghostTo is saved in entry.to at creation (line 570).
        // FIX: SPEC-03 — expose the type byte (frame[2]) in the emitted event.
        // Type codes: 0x01=text, 0x02=ack, 0x03=ping (MSG_TYPE in stego-core/index.js).
        const frameType = frame[2]; // FIX: SPEC-03 read type byte
        console.log(`[VS3] Frame assembled from ${miner.wallet?.slice(0,12)}... → ${miner.ghostTo?.slice(0,12) || 'broadcast'} (${frame.length}B)`);
        this.emit('vs3-frame', { from: miner.wallet, to: miner.ghostTo || null, frame, type: frameType }); // FIX: BUG-04, SPEC-03
        miner.ghostTo = null; // reset after delivery
      } else {
        // Multi-fragment message: accumulate until all pieces arrive.
        if (!miner.fragmentBuffers) miner.fragmentBuffers = new Map(); // FIX: SPEC-04
        if (!miner.fragmentBuffers.has(msgId)) {
          // First time seeing this message_id: initialize the structure
          // and arm a 30s timeout to discard incomplete fragments.
          const timer = setTimeout(() => {
            if (miner.fragmentBuffers && miner.fragmentBuffers.has(msgId)) {
              console.warn(`[VS3] Fragment timeout for message_id=0x${msgId.toString(16)} — discarded`); // FIX: SPEC-04
              miner.fragmentBuffers.delete(msgId);
            }
          }, 30000); // FIX: SPEC-04 30-second timeout
          miner.fragmentBuffers.set(msgId, {
            fragments: new Array(fragTotal).fill(null),
            received: 0,
            total: fragTotal,
            header: frame.slice(0, 8), // preserve header from first fragment
            timer,
            // FIX: BUG-04 — the to field is associated with message_id, not the TCP session.
            // Use miner.ghostTo (persisted from the first share carrying vs3_to).
            to: miner.ghostTo
          });
        }
        const entry = miner.fragmentBuffers.get(msgId);
        // FIX: M-3 — validate that fragTotal matches the existing entry.
        // A mismatch means a corrupted or spoofed frame; discard it.
        if (entry && entry.total !== fragTotal) {
          console.warn(`[VS3] fragment_total mismatch for message_id=0x${msgId.toString(16)}: expected ${entry.total}, got ${fragTotal} — discarded`);
          continue;
        }
        if (entry && entry.fragments[fragIndex] === null) {
          entry.fragments[fragIndex] = fragPayload;
          entry.received++;
          if (entry.received === entry.total) {
            // All fragments received: concatenate payload and reassemble frame.
            clearTimeout(entry.timer); // FIX: SPEC-04 cancel timeout
            miner.fragmentBuffers.delete(msgId);
            const fullPayload = Buffer.concat(entry.fragments);
            // FIX: M-4 — payload_len is uint8 (max 255). If reassembled
            // payload exceeds 255 bytes, discard: it cannot be represented
            // in the VS3 frame header. The proxy (vs3-proxy.js) already has
            // this guard; stratum-demo was missing it.
            if (fullPayload.length > 255) {
              console.warn(`[VS3] Reassembled payload too large (${fullPayload.length}B > 255) for message_id=0x${msgId.toString(16)} — discarded`);
              continue;
            }
            // Reassemble a synthetic frame with the complete payload.
            const reassembled = Buffer.alloc(GHOST_HEADER + fullPayload.length);
            entry.header.copy(reassembled, 0);
            reassembled[5] = 0;                   // fragment_index = 0
            reassembled[6] = 1;                   // fragment_total = 1 (now complete)
            reassembled[7] = fullPayload.length;  // update payload_len
            fullPayload.copy(reassembled, GHOST_HEADER);
            console.log(`[VS3] Multi-fragment message_id=0x${msgId.toString(16)} reassembled (${entry.total} fragments, ${reassembled.length}B)`); // FIX: SPEC-04
            // FIX: BUG-04 — use entry.to (associated with message_id) instead of miner.ghostTo.
            // FIX: SPEC-03 — expose the type byte (reassembled[2]) in the emitted event.
            // Type codes: 0x01=text, 0x02=ack, 0x03=ping (MSG_TYPE in stego-core/index.js).
            this.emit('vs3-frame', { from: miner.wallet, to: entry.to, frame: reassembled, type: reassembled[2] }); // FIX: BUG-04, SPEC-03
            miner.ghostTo = null; // reset after delivery (mirrors single-fragment path)
          }
        }
      }
    }
  }

  // ── VS3 Download Path: pool → miner ────────────────────────────────────
  //
  // routeVS3 is the entry point for delivering a VS3 frame to a specific
  // recipient miner. It queues the frame in miner.pendingFrames; the frame
  // is then injected into the next outgoing job notification (see _makeJob).
  //
  // KEY DESIGN INSIGHT — why job notifications?
  //   The pool's existing mechanism for pushing new work to miners (the "job"
  //   JSON-RPC notification) is repurposed as the encapsulated downlink channel.
  //   No new message type, no new TCP connection, no additional port, no
  //   detectable behavioral change. From the network observer's perspective,
  //   job notifications arrive at the same rate as without VS3.
  //
  // Returns true if the recipient is currently connected, false if offline.
  // Callers that receive false may retry later or queue frames externally.
  //
  routeVS3(recipientWallet, frame) {
    for (const [,m] of this.miners) {
      if (m.wallet === recipientWallet && m.authorized) {
        m.pendingFrames = m.pendingFrames || [];
        m.pendingFrames.push(frame);
        // Immediately push a job notification to the recipient so the frame
        // is delivered without waiting for the next block template update.
        // This is the intended VS3 delivery trigger (see _sendJob comment).
        this._sendJob(m);
        return true;
      }
    }
    return false;
  }

  _makeJob(miner) {
    // Standard Stratum job object. Fields are as required by the XMRig spec:
    //   job_id    — unique identifier for this job (used in submit messages)
    //   target    — difficulty target in compact form ('ffffffff' = diff 1)
    //   blob      — the block template hex blob to hash
    //   height    — current blockchain height (needed by RandomX)
    //   seed_hash — RandomX dataset seed (changes every 2048 blocks)
    //
    // Ghost share senders are assigned difficulty 1 (target 'ffffffff') so
    // they can submit shares as frequently as needed without real mining work.
    //
    const jobId = crypto.randomBytes(4).toString('hex');
    const bt = this.blockTemplate;
    const job = {
      job_id: jobId,
      target: 'ffffffff',
      blob: bt?.blocktemplate_blob || '0'.repeat(152),
      height: bt?.height || 0,
      seed_hash: bt?.seed_hash || '0'.repeat(64),
    };
    // ── VS3 frame injection (download path) ─────────────────────────────
    //
    // If a VS3 frame is queued for this miner, it is attached to the job
    // notification as a hex-encoded "vs3" extension field.
    //
    // From the network observer's perspective, "vs3" is just an unrecognized
    // extra field in a standard Stratum JSON object — the same as any pool-
    // specific extension (fee metadata, work multipliers, etc.). XMRig and
    // other standard clients ignore unknown fields without error.
    //
    // A VS3-aware client reads this field, decodes the hex back to bytes,
    // and passes the frame to the decryption and delivery pipeline.
    //
    // One frame per job is delivered to bound job notification size. If
    // multiple frames are pending they are delivered in subsequent jobs
    // (triggered by block template updates or explicit _sendJob calls).
    //
    if (miner.pendingFrames?.length) {
      job.vs3 = miner.pendingFrames.shift().toString('hex');
    }
    // FIX: BUG-07 — cap this.jobs at 50 entries (FIFO) to prevent memory leak.
    // Jobs are added but never removed: without this cap the Map grows
    // unboundedly for the lifetime of the process. The jobs field exists for
    // future job_id validation in submits (not yet implemented in this demo).
    this.jobs.set(jobId, job);
    if (this.jobs.size > 50) {
      // Remove oldest entry (first key inserted in the Map).
      this.jobs.delete(this.jobs.keys().next().value); // FIX: BUG-07 FIFO eviction
    }
    return job;
  }

  _sendJob(miner) {
    // Unsolicited job push via the standard Stratum "job" notification method.
    // XMRig expects these whenever the pool has new work (new block, new
    // difficulty). VS3 can also trigger a job push specifically to deliver a
    // queued frame to a recipient miner without waiting for the next natural
    // block template update.
    const job = this._makeJob(miner);
    this._send(miner, { jsonrpc:'2.0', method:'job', params: job });
  }

  _send(miner, msg) {
    // Newline-delimited JSON: each message is a single UTF-8 line terminated
    // with '\n'. Errors are suppressed here; the 'close' event on the socket
    // handles cleanup and counter decrement.
    try { miner.sock.write(JSON.stringify(msg) + '\n'); } catch(_) {}
  }
}

// ── Stats API ───────────────────────────────────────────────────────────────
//
// A single-endpoint HTTP server for operational monitoring. Exposes:
//   connected   — number of miners currently connected
//   ghostShares — cumulative ghost shares received since startup
//   vs3Frames   — cumulative complete VS3 frames reassembled since startup
//   uptime      — process uptime in seconds
//
// CORS is open (*) to allow browser-based monitoring dashboards without a
// proxy. In a production deployment this endpoint would be firewalled or
// protected; it is useful for observing VS3 activity in real time
// while running the companion demo client.
//
function startAPI(stratum) {
  http.createServer((req, res) => {
    if (req.url !== '/stats') { res.writeHead(404); res.end(); return; }
    // FIX: SEC-04 — removed Access-Control-Allow-Origin: * from /stats endpoint.
    // This endpoint is for local/admin use and should not be accessible cross-origin:
    // open CORS would expose VS3 counters to any browser origin.
    res.writeHead(200, { 'Content-Type':'application/json' });
    res.end(JSON.stringify({ ...stratum.stats, uptime: process.uptime() }));
  }).listen(CFG.apiPort, () => console.log(`[VS3-Demo] Stats API on :${CFG.apiPort}/stats`));
}

// ── Main ────────────────────────────────────────────────────────────────────
//
// Wire up the VS3 frame event handler. In this demo we decode the frame
// payload as UTF-8 text and log it, demonstrating end-to-end delivery.
//
// In a full implementation the handler would pass the frame to an encryption
// layer (X25519 key agreement + XChaCha20-Poly1305, HKDF-SHA256) before presenting
// the plaintext to the user interface.
//
const stratum = new StratumDemo();
// FIX: SPEC-03 — destructuring now includes `type` (frame[2]), exposed by emit.
stratum.on('vs3-frame', ({ from, to, frame, type }) => {
  // frame[0..7] = VS3 header (see frame format above)
  // frame[8..]  = plaintext payload (in this demo; encrypted in production)
  // type = frame[2]: 0x01=text, 0x02=ack, 0x03=ping (MSG_TYPE in stego-core/index.js)
  const text = frame.slice(8, 8 + frame[7]).toString('utf8');
  console.log(`[VS3] Message: "${text}" | from=${from?.slice(0,12)} to=${to?.slice(0,12)||'broadcast'} type=0x${(type||0).toString(16).padStart(2,'0')}`);
  // Route the assembled frame to the recipient miner (download path).
  // routeVS3 queues the frame in the recipient's pendingFrames and
  // immediately triggers a job push so delivery does not depend on the
  // next block template update (which may not arrive without a live daemon).
  if (to) stratum.routeVS3(to, frame);
});
stratum.start();
startAPI(stratum);
console.log('[VS3-Demo] TNZX VS3 Protocol Reference Implementation');
console.log(`[VS3-Demo] Daemon: ${CFG.daemonHost}:${CFG.daemonPort}`);
