'use strict';
/**
 * vs3-client.js — VS3 bidirectional communication client (POC)
 *
 * Demonstrates the complete VS3 protocol round-trip over standard Stratum:
 *
 *   SENDER:   connects as a miner, encodes a text message in ghost shares,
 *             submits them to the pool addressed to a recipient wallet address.
 *
 *   LISTENER: connects as a miner, reads every incoming job notification,
 *             extracts and displays any VS3 frame embedded in the "vs3" field.
 *
 *   CHAT:     connects as a miner, sends and receives messages interactively.
 *             Both parties run in chat mode — full bidirectional communication.
 *
 * All connections use standard Stratum: login, submit, and job messages.
 * The "vs3" extension field in job notifications is an unrecognized field
 * that standard miners (XMRig) silently ignore.
 *
 * ─── HOW TO RUN — one-way demo (no Monero daemon required) ──────────────────
 *
 *   Terminal 1 — pool:     node src/stratum-demo.js
 *   Terminal 2 — Bob:      .\bob.ps1
 *   Terminal 3 — Alice:    .\alice.ps1
 *
 * ─── HOW TO RUN — bidirectional chat ────────────────────────────────────────
 *
 *   Terminal 1 — pool:     node src/stratum-demo.js
 *   Terminal 2 — Bob:      .\bob-chat.ps1
 *   Terminal 3 — Alice:    .\alice-chat.ps1
 *
 *   Both parties type messages and press Enter. Received messages appear
 *   inline with the sender's [you] prompt restored automatically.
 *
 * Environment variables (optional): HOST (default 127.0.0.1), PORT (default 4444)
 *
 * What to observe:
 *   - Pool log shows: [VS3] Frame assembled from 4222... → 4111... (NN B)
 *   - Recipient terminal shows: [VS3] ← Message received: "..."
 *   - No message content is visible in the ghost share submissions
 *
 * @license LGPL-2.1
 */

const net      = require('net');
const readline = require('readline');

// ─── Argument parsing ────────────────────────────────────────────────────────

const mode     = process.argv[2];
const myWallet = process.argv[3];
const toWallet = (mode === 'send' || mode === 'chat') ? process.argv[4] : null;
const message  = mode === 'send' ? process.argv.slice(5).join(' ') : null;
const HOST     = process.env.HOST || '127.0.0.1';
const PORT     = parseInt(process.env.PORT || '4444');

if (!['listen','send','chat'].includes(mode) || !myWallet ||
    (mode === 'send' && (!toWallet || !message)) ||
    (mode === 'chat' && !toWallet)) {
  console.error('Usage:');
  console.error('  Listen:  node vs3-client.js listen  <myWallet>');
  console.error('  Send:    node vs3-client.js send    <myWallet> <toWallet> <message...>');
  console.error('  Chat:    node vs3-client.js chat    <myWallet> <toWallet>');
  console.error('');
  console.error('Env: HOST (default 127.0.0.1), PORT (default 4444)');
  process.exit(1);
}

// ─── VS3 frame and share encoding ────────────────────────────────────────────
//
// These helpers mirror the encoding in stratum-demo.js and test-ghost.js.
// See those files for detailed commentary on the steganographic field
// layout and why each value is chosen.
//
// Frame format (8-byte header + N-byte payload):
//   [0xAA][0x03][0x01][0x00][0x01][0x00][0x01][payload_len][...payload...]
//    magic  ver  type   message_id   frag_idx  frag_tot  len
//
// Ghost share encoding (5 bytes per share):
//   nonce  = 0xAA | payload[0..2]   (marker + 3 bytes)
//   ntime  = real_epoch_hi | payload[3..4]  (2 bytes in low word)

function buildVS3Frame(text) {
  const payload = Buffer.from(text, 'utf8').slice(0, 247); // max 1-byte payload_len
  return Buffer.concat([
    Buffer.from([0xAA, 0x03, 0x01, 0x00, 0x01, 0x00, 0x01, payload.length]),
    payload
  ]);
}

function chunkFrame(frameBytes) {
  const chunks = [];
  for (let i = 0; i < frameBytes.length; i += 5) {
    const c = Buffer.alloc(5, 0); // zero-pad last chunk if frame length % 5 ≠ 0
    frameBytes.copy(c, 0, i, Math.min(i + 5, frameBytes.length));
    chunks.push(c);
  }
  return chunks;
}

function encodeGhostShare(reqId, minerId, jobId, chunk, vs3To) {
  const nonce    = 'aa' +
    chunk[0].toString(16).padStart(2, '0') +
    chunk[1].toString(16).padStart(2, '0') +
    chunk[2].toString(16).padStart(2, '0');
  const now      = Math.floor(Date.now() / 1000);
  const ntimeVal = ((now & 0xFFFF0000) | (chunk[3] << 8) | chunk[4]) >>> 0;
  const ntime    = ntimeVal.toString(16).padStart(8, '0');
  const params   = { id: minerId, job_id: jobId, nonce, result: '0'.repeat(64), ntime };
  if (vs3To) params.vs3_to = vs3To;
  return JSON.stringify({ id: reqId, jsonrpc: '2.0', method: 'submit', params });
}

// ─── Connection banner ────────────────────────────────────────────────────────

const modeLabel = { listen: 'Listener', send: 'Sender', chat: 'Chat' }[mode];
console.log(`[VS3] ${modeLabel} → ${HOST}:${PORT}`);
console.log(`[VS3] My wallet : ${myWallet.slice(0, 12)}...`);
if (mode === 'send') {
  console.log(`[VS3] Recipient : ${toWallet.slice(0, 12)}...`);
  console.log(`[VS3] Message   : "${message}"`);
}
if (mode === 'chat') {
  console.log(`[VS3] Chat with : ${toWallet.slice(0, 12)}...`);
}
console.log();

// ─── Stratum connection ───────────────────────────────────────────────────────

const sock = net.connect(PORT, HOST, () => {
  let buf = '', minerId = null, jobId = null, step = 0, chatStarted = false;

  sock.on('data', (d) => {
    buf += d.toString();
    const lines = buf.split('\n');
    buf = lines.pop(); // retain incomplete trailing line

    for (const line of lines) {
      if (!line.trim()) continue;
      let msg; try { msg = JSON.parse(line); } catch (_) { continue; }

      // ── Login response ───────────────────────────────────────────────────
      //
      // Standard Stratum login response: { id:1, result:{ id, job, status } }
      // The miner session id (result.id) is required for share submissions.
      //
      if (step === 0 && msg.id === 1 && msg.result) {
        minerId = msg.result.id;
        jobId   = msg.result.job?.job_id;
        step    = 1;

        if (mode === 'listen') {
          console.log('[VS3] Connected. Waiting for messages...');
          console.log('      (Ctrl+C to exit)\n');
        } else if (mode === 'send' && jobId) {
          sendMessage();
        } else if (mode === 'chat' && jobId) {
          startChatMode();
        }
      }

      // ── Incoming job notification ────────────────────────────────────────
      //
      // Standard Stratum job: { method:"job", params:{ job_id, target, blob, ... } }
      // VS3 extension: params.vs3 = hex-encoded frame bytes, present only when
      // the pool has routed a complete frame to this wallet address.
      // XMRig and other standard miners ignore unknown params fields silently.
      //
      if (msg.method === 'job' && msg.params) {
        if (msg.params.job_id) jobId = msg.params.job_id;

        // Chat mode: start interactive interface on first job if not yet started
        if (mode === 'chat' && step === 1 && !chatStarted) {
          startChatMode();
        }

        if ((mode === 'listen' || mode === 'chat') && msg.params.vs3) {
          const frame = Buffer.from(msg.params.vs3, 'hex');

          // Validate: must begin with VS3 magic byte and have at least a header
          if (frame.length >= 9 && frame[0] === 0xAA) {
            const payloadLen = frame[7];
            const text       = frame.slice(8, 8 + payloadLen).toString('utf8');
            const ts         = new Date().toISOString().slice(11, 19);
            if (mode === 'chat' && sock._vs3rl) {
              // Erase the current input line so the message prints cleanly,
              // then redraw the prompt (and any partial input) below it.
              readline.clearLine(process.stdout, 0);
              readline.cursorTo(process.stdout, 0);
            }
            console.log(`[VS3] ← Message received at ${ts}:`);
            console.log(`      "${text}"`);
            console.log(`      (frame: ${frame.length}B, version: 0x${frame[1].toString(16).padStart(2,'0')}, type: 0x${frame[2].toString(16).padStart(2,'0')})`);
            console.log();
            if (mode === 'chat' && sock._vs3rl) {
              sock._vs3rl.prompt(true);
            }
          }
        }
      }
    }
  });

  // ── Send mode: ghost share transmission ──────────────────────────────────
  //
  // Builds a VS3 frame from the message string, splits it into 5-byte chunks,
  // and submits each chunk as a Stratum share at 200 ms intervals.
  // The first share carries the vs3_to field (recipient wallet); subsequent
  // shares omit it — the pool retains the routing target for the full frame.
  //
  function sendMessage() {
    const frame  = buildVS3Frame(message);
    const chunks = chunkFrame(frame);
    console.log(`[VS3] Frame: ${frame.length}B → ${chunks.length} ghost shares`);

    let reqId = 10, i = 0;
    const iv = setInterval(() => {
      if (i >= chunks.length) {
        clearInterval(iv);
        console.log('\n[VS3] All shares sent. Closing connection.');
        setTimeout(() => sock.destroy(), 400);
        return;
      }
      const m     = encodeGhostShare(reqId++, minerId, jobId, chunks[i], i === 0 ? toWallet : null);
      const nonce = JSON.parse(m).params.nonce;
      console.log(`      Share ${String(i + 1).padStart(2)}/${chunks.length} → nonce=${nonce}`);
      sock.write(m + '\n');
      i++;
    }, 200);
  }

  // ── Chat mode: interactive bidirectional messaging ────────────────────────
  //
  // Both parties run: node vs3-client.js chat <myWallet> <otherWallet>
  // Each side can type messages at any time; received messages are displayed
  // inline with prompt restoration. Sending is non-blocking: subsequent
  // keypresses while a transmission is in flight are queued by readline.
  //
  function startChatMode() {
    if (chatStarted) return;
    chatStarted = true;
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    rl.setPrompt('[you] ');
    let sending = false;
    let reqId = 100;

    // Expose rl so the data handler can redraw the prompt when a message arrives
    sock._vs3rl = rl;

    console.log('[VS3] Chat ready. Type a message and press Enter. (Ctrl+C to exit)\n');
    rl.prompt();

    rl.on('line', (input) => {
      const text = input.trim();
      if (!text || sending || !jobId || !minerId) {
        if (!sending) rl.prompt();
        return;
      }
      sending = true;
      const frame  = buildVS3Frame(text);
      const chunks = chunkFrame(frame);
      let i = 0;
      const iv = setInterval(() => {
        if (i >= chunks.length) {
          clearInterval(iv);
          sending = false;
          rl.prompt();
          return;
        }
        sock.write(encodeGhostShare(reqId++, minerId, jobId, chunks[i], i === 0 ? toWallet : null) + '\n');
        i++;
      }, 200);
    });

    rl.on('close', () => sock.destroy());
  }

  // Initiate standard Stratum handshake
  sock.write(JSON.stringify({
    id: 1, jsonrpc: '2.0', method: 'login',
    params: { login: myWallet, pass: 'x', agent: 'vs3-client/1.0' }
  }) + '\n');
});

sock.on('error', (e) => console.error(`[VS3] Socket error: ${e.message}`));
sock.on('close', () => { if (mode === 'listen') console.log('[VS3] Disconnected.'); });
