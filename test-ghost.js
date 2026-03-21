'use strict';
/**
 * test-ghost.js — Ghost Share steganography proof-of-concept for TNZX
 *
 * This script demonstrates the core privacy primitive of the TNZX protocol:
 * arbitrary binary data ("VS3 frames") can be transmitted covertly through a
 * standard Stratum mining pool, hidden inside otherwise-valid share submissions.
 *
 * HOW TO RUN:
 *   node test-ghost.js [host] [port]
 *   Example: node test-ghost.js 127.0.0.1 4444
 *
 * WHAT TO OBSERVE IN THE POOL LOG:
 *   - Each incoming share is accepted normally (no Stratum protocol violation).
 *   - Once all chunks arrive, the pool emits: [VS3] Ghost frame assembled
 *   - The reassembled payload matches the original text sent by this script.
 *   - The shares are structurally valid Stratum submissions at the protocol level.
 *
 * PROTOCOL SUMMARY:
 *   1. Connect to pool via standard Stratum JSON-RPC over TCP.
 *   2. Log in with a well-formed (but throwaway) Monero wallet address.
 *   3. Encode a VS3 binary frame into 5-byte chunks.
 *   4. Submit each chunk as a share, hiding the bytes inside `nonce` and `ntime`.
 *   5. The pool reassembles the frame transparently upon receiving all chunks.
 */

const net = require('net');
const HOST = process.argv[2] || '127.0.0.1';
const PORT = parseInt(process.argv[3]) || 4444;

// A syntactically valid (but unused) Monero mainnet address — satisfies pool
// address-format validation without being tied to any real wallet.
const FAKE_WALLET = '4' + '1'.repeat(94);

/**
 * buildVS3Frame(text) — Serialize a UTF-8 string into a VS3 binary frame.
 *
 * VS3 frame layout per protocol spec (8-byte header + variable payload):
 *
 *   Byte 0:   0xAA  — VS3 magic / start-of-frame marker
 *   Byte 1:   0x03  — protocol version (0x03 = VS3, per stego-core VERSION_V3 constant)
 *   Byte 2:   0x01  — frame type (0x01 = text message, per MSG_TYPE.TEXT)
 *   Bytes 3–4: 0x00, 0x01 — message_id big-endian (first message = 1)
 *   Byte 5:   0x00  — fragment_index (0-based; 0 for single-fragment messages)
 *   Byte 6:   0x01  — fragment_total (1 = no fragmentation)
 *   Byte 7:   payload.length — byte count N of the payload that follows
 *   Bytes 8…8+N: UTF-8 payload (capped at 247 bytes; payload_len field is 1 byte)
 *
 * Total frame size = 8 + payload.length bytes.
 * The pool parser reads exactly frame[7] bytes after the 8-byte header.
 */
function buildVS3Frame(text) {
  const payload = Buffer.from(text, 'utf8').slice(0, 247);
  return Buffer.concat([
    Buffer.from([0xAA, 0x03, 0x01, 0x00, 0x01, 0x00, 0x01, payload.length]),
    payload
  ]);
}

/**
 * chunkFrame(frameBytes) — Split a VS3 frame into 5-byte steganographic chunks.
 *
 * WHY 5 BYTES PER CHUNK — the heart of the steganography:
 *   A Stratum share submission contains two miner-controlled fields:
 *     • nonce  — 4 hex bytes (32 bits) submitted by the miner
 *     • ntime  — 4 hex bytes (32 bits) representing the block timestamp
 *
 *   Of these 8 bytes, 5 can carry hidden payload without triggering pool rejection:
 *     - 3 bytes encoded into the lower 3 bytes of `nonce` (byte 0 is the 0xAA marker)
 *     - 2 bytes encoded into the lower 16 bits of `ntime` (upper 16 bits stay real)
 *
 *   This gives exactly 5 hidden payload bytes per share, with no modification to
 *   any field that the pool's job-validation logic checks for structural correctness.
 *   The pool can therefore accept every ghost share as a valid Stratum submission
 *   while simultaneously extracting and reassembling the hidden VS3 frame.
 *
 *   Each chunk is zero-padded to exactly 5 bytes so the final share (which may
 *   carry fewer than 5 real bytes) remains a well-formed, fixed-width submission.
 */
function chunkFrame(frameBytes) {
  const chunks = [];
  for (let i = 0; i < frameBytes.length; i += 5) {
    const c = Buffer.alloc(5, 0); // zero-pad to guarantee a full 5-byte width
    frameBytes.copy(c, 0, i, Math.min(i + 5, frameBytes.length));
    chunks.push(c);
  }
  return chunks;
}

/**
 * encodeGhostShare(reqId, minerId, jobId, chunk, vs3To)
 *
 * Encode one 5-byte chunk into a standard Stratum `mining.submit` JSON message.
 *
 * ENCODING SCHEME — how the 5 payload bytes map to Stratum fields:
 *
 *   chunk[0..2] → `nonce` (8 hex chars = 4 bytes):
 *     nonce = 0xAA | chunk[0] | chunk[1] | chunk[2]
 *     The leading 0xAA byte is the VS3 ghost-share marker. It lets the pool
 *     identify ghost submissions without any out-of-band signalling channel:
 *     any share whose nonce starts with AA is a VS3 carrier, not a PoW attempt.
 *
 *   chunk[3..4] → `ntime` (8 hex chars = 4 bytes):
 *     ntimeVal = (now & 0xFFFF0000) | (chunk[3] << 8) | chunk[4]
 *     The upper 16 bits are taken from the real wall-clock Unix timestamp,
 *     keeping the value within a plausible range to pass pool timestamp checks.
 *     The lower 16 bits carry the two hidden payload bytes. The pool recovers
 *     them by masking (ntimeVal & 0x0000FFFF).
 *
 *   `result` — 64 zero hex characters: a deliberately invalid proof-of-work.
 *     Ghost shares are not expected to solve the current job. The pool accepts
 *     them for VS3 data extraction regardless of PoW validity, treating them
 *     as a separate data path distinct from the mining reward path.
 *
 * @param {number}      reqId   — JSON-RPC request id (monotonically increasing)
 * @param {string}      minerId — miner session id assigned by the pool at login
 * @param {string}      jobId   — current job id issued by the pool
 * @param {Buffer}      chunk   — exactly 5 bytes of VS3 frame payload
 * @param {string|null} vs3To  — destination address; non-null only on the first share
 */
function encodeGhostShare(reqId, minerId, jobId, chunk, vs3To) {
  // Bytes 0-2 map to the lower 3 bytes of the nonce field.
  // The 0xAA prefix marks this share as a VS3 ghost carrier.
  const nonce = 'aa' +
    chunk[0].toString(16).padStart(2, '0') +
    chunk[1].toString(16).padStart(2, '0') +
    chunk[2].toString(16).padStart(2, '0');

  // Bytes 3-4 map to the lower 16 bits of ntime.
  // The upper 16 bits are borrowed from the current Unix timestamp so the
  // value looks like a real block time to the pool's range validator.
  const now = Math.floor(Date.now() / 1000);
  const ntimeVal = ((now & 0xFFFF0000) | (chunk[3] << 8) | chunk[4]) >>> 0;
  const ntime = ntimeVal.toString(16).padStart(8, '0');

  const params = { id: minerId, job_id: jobId, nonce, result: '0'.repeat(64), ntime };

  // vs3_to is the destination wallet address for the hidden message.
  // It is attached ONLY to the first share of each frame sequence:
  //   - Repeating it on every share would be redundant and slightly increases
  //     the statistical footprint of the covert channel.
  //   - The pool reads vs3_to once from chunk index 0 and retains it internally
  //     for the full frame reassembly; all subsequent shares omit the field.
  if (vs3To) params.vs3_to = vs3To;

  return JSON.stringify({ id: reqId, jsonrpc: '2.0', method: 'submit', params });
}

// ─── Main connection flow ─────────────────────────────────────────────────────
//
// The client follows the standard Stratum handshake before injecting ghost shares:
//
//   Step 0 — LOGIN:  Send `mining.login` with the fake wallet address.
//                    The pool responds with a miner session id and, optionally,
//                    an immediately available job bundled in the same response.
//   Step 1 — JOB:    If no job was bundled in the login response, wait for the
//                    pool to push one via an unsolicited `job` notification.
//   Step 2 — GHOST:  Once a valid job_id is known, transmit all ghost shares in
//                    sequence (one per 200 ms) to avoid TCP send-buffer pressure.
//                    The pool reassembles the VS3 frame and logs confirmation.
//
const sock = net.connect(PORT, HOST, () => {
  console.log(`Connesso a ${HOST}:${PORT}`);
  let buf = '', jobId = null, minerId = null, step = 0;

  sock.on('data', (d) => {
    buf += d.toString();
    // Stratum messages are newline-delimited JSON; buffer any partial trailing line.
    const lines = buf.split('\n');
    buf = lines.pop(); // retain incomplete line for the next data event
    for (const line of lines) {
      if (!line.trim()) continue;
      let msg; try { msg = JSON.parse(line); } catch (_) { continue; }
      console.log('← Pool:', JSON.stringify(msg).slice(0, 140));

      // Step 0 → 1: login response. Extract miner session id and optional job_id.
      if (step === 0 && msg.id === 1 && msg.result) {
        minerId = msg.result.id;
        jobId   = msg.result.job?.job_id;
        step = 1;
        if (jobId) {
          // FIX: BUG-03+COMPAT-01 — portare step a 2 PRIMA di chiamare sendGhostMessage()
          // così l'eventuale notifica job separata che arriva subito dopo il login
          // non trigghera un secondo invio (step sarà già 2, non 1).
          step = 2; // FIX: BUG-03 avanza step prima dell'invio
          console.log('\nLogin OK. Invio ghost shares...\n');
          sendGhostMessage();
        } else { console.log('Login OK. Aspetto job...'); }

      // Step 1 → 2: pool pushes a job notification (the common path when the pool
      // did not bundle a job inside the login response).
      } else if (msg.method === 'job' && msg.params?.job_id && step === 1) {
        jobId = msg.params.job_id;
        step = 2; // FIX: BUG-03 step avanzato qui solo se eravamo ancora a 1
        console.log(`\nJob: ${jobId}. Invio ghost shares...\n`);
        sendGhostMessage();
      }
    }
  });

  /**
   * sendGhostMessage() — Build and transmit the full ghost-share sequence.
   *
   * Encodes the demo string into a VS3 frame, splits it into 5-byte chunks,
   * and sends one Stratum `mining.submit` per chunk at 200 ms intervals.
   * The first share carries `vs3_to` (the destination address); all subsequent
   * shares omit it — the pool retains it from chunk 0 for the entire frame.
   */
  function sendGhostMessage() {
    const frame = buildVS3Frame('Ciao dal test ghost share TNZX!');
    const chunks = chunkFrame(frame);
    console.log(`Frame: ${frame.length}B → ${chunks.length} ghost shares`);
    let reqId = 10, i = 0;
    // FIX: COMPAT-02 — flow control con backpressure semplice basato su inFlight.
    // Il client inviava share ogni 200ms senza attendere OK dal server, causando
    // burst non controllati in presenza di latenza o buffer pieno lato server.
    let inFlight = 0; // FIX: COMPAT-02 contatore share in volo (inviati, non ancora OK ricevuto)
    const INFLIGHT_MAX = 3; // FIX: COMPAT-02 soglia backpressure: non superare 3 share in volo

    // FIX: COMPAT-02 — gestione risposta OK agli share: decrementa inFlight.
    // L'handler dati esistente (sopra) gestisce il login/job; aggiungiamo qui
    // la gestione delle risposte agli share (id >= 10, result.status === 'OK').
    sock.on('data', (d) => {
      // Nota: il buffer buf è gestito dall'handler principale sopra; qui processiamo
      // solo le risposte agli share per decrementare inFlight.
      const raw = d.toString();
      for (const line of raw.split('\n')) {
        if (!line.trim()) continue;
        let r; try { r = JSON.parse(line); } catch (_) { continue; }
        // Le risposte agli share hanno id >= 10 e result.status === 'OK'.
        if (r.id >= 10 && r.result?.status === 'OK') {
          inFlight = Math.max(0, inFlight - 1); // FIX: COMPAT-02 decrementa inFlight
        }
      }
    });

    const iv = setInterval(() => {
      if (i >= chunks.length) {
        clearInterval(iv);
        console.log('\nFatto. Controlla log pool per "[VS3] Ghost frame assembled".');
        setTimeout(() => sock.destroy(), 1000);
        return;
      }
      // FIX: COMPAT-02 — backpressure: se ci sono già INFLIGHT_MAX share in volo,
      // salta questo tick e aspetta che il server risponda prima di inviare altri.
      if (inFlight >= INFLIGHT_MAX) return; // FIX: COMPAT-02 aspetta OK prima di proseguire
      // vs3_to is passed only for i === 0; null for all remaining shares.
      const m = encodeGhostShare(reqId++, minerId, jobId, chunks[i], i === 0 ? FAKE_WALLET : null);
      console.log(`→ Share ${i+1}/${chunks.length}: nonce=${JSON.parse(m).params.nonce}`);
      sock.write(m + '\n');
      inFlight++; // FIX: COMPAT-02 incrementa inFlight dopo ogni write
      i++;
    }, 200);
  }

  // Kick off Step 0: standard Stratum login handshake.
  sock.write(JSON.stringify({
    id: 1, jsonrpc: '2.0', method: 'login',
    params: { login: FAKE_WALLET, pass: 'x', agent: 'test-ghost/1.0' }
  }) + '\n');
});

sock.on('error', (e) => console.error('Errore:', e.message));
sock.on('close', () => console.log('Connessione chiusa.'));
