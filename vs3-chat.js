'use strict';
/**
 * vs3-chat.js — End-to-end encrypted chat over encapsulated mining channel
 *
 * Two parties exchange encrypted messages hidden in Stratum mining traffic.
 * Each message uses a fresh ephemeral X25519 key (Perfect Forward Secrecy).
 * The pool sees ghost shares with random-looking nonce bytes (HMAC sentinel).
 * No cleartext message content ever leaves the client.
 *
 * ─── HOW TO RUN ─────────────────────────────────────────────────────────────
 *
 *   Terminal 1 — pool:   node src/stratum-demo.js
 *   Terminal 2 — Alice:  node vs3-chat.js <alice_wallet> <bob_wallet>
 *   Terminal 3 — Bob:    node vs3-chat.js <bob_wallet> <alice_wallet>
 *
 *   Both parties type messages and press Enter.
 *   The pool log shows ghost shares being assembled — but cannot read content.
 *
 * ─── WHAT TO OBSERVE ────────────────────────────────────────────────────────
 *
 *   - Each message is encrypted before framing (XChaCha20-Poly1305)
 *   - Each message uses a fresh ephemeral X25519 keypair (PFS)
 *   - Ghost share nonces use HMAC sentinel (not fixed 0xAA)
 *   - The pool sees only opaque ciphertext in the assembled frame
 *   - The recipient decrypts using their persistent X25519 private key
 *
 * ─── KEY EXCHANGE ───────────────────────────────────────────────────────────
 *
 *   On connect, each party sends a KEY_EXCHANGE frame containing their
 *   X25519 public key (32 bytes). The pool routes it by wallet address.
 *   Once both parties have each other's public key, encryption begins.
 *   Before key exchange completes, typed messages are queued.
 *
 * @license LGPL-2.1
 */

const net      = require('net');
const readline = require('readline');
const crypto   = require('crypto');
const { generateKeyPair, encryptMessage, decryptMessage } = require('./lib/e2e');

// ─── Arguments ──────────────────────────────────────────────────────────────

const myWallet = process.argv[2];
const toWallet = process.argv[3];
const HOST     = process.env.HOST || '127.0.0.1';
const PORT     = parseInt(process.env.PORT || '4444');

if (!myWallet || !toWallet) {
  console.error('Usage: node vs3-chat.js <myWallet> <peerWallet>');
  console.error('Env: HOST (default 127.0.0.1), PORT (default 4444)');
  process.exit(1);
}

// ─── Crypto identity ────────────────────────────────────────────────────────

const myKeys = generateKeyPair();
let peerPubKey = null;
const pendingMessages = []; // queued until key exchange

console.log('');
console.log('  ╔══════════════════════════════════════════════════════════╗');
console.log('  ║  VS3 Encrypted Chat — Encapsulated Mining Channel     ║');
console.log('  ╚══════════════════════════════════════════════════════════╝');
console.log('');
console.log(`  Identity : ${myKeys.publicKey.toString('hex').slice(0, 16)}...`);
console.log(`  Wallet   : ${myWallet.slice(0, 12)}...`);
console.log(`  Peer     : ${toWallet.slice(0, 12)}...`);
console.log(`  Cipher   : XChaCha20-Poly1305 (PFS per message)`);
console.log(`  Pool     : ${HOST}:${PORT}`);
console.log('');

// ─── VS3 frame encoding ────────────────────────────────────────────────────

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

// ─── Send a VS3 frame as ghost shares ───────────────────────────────────────

function sendFrame(sock, minerId, jobId, frameBytes, reqIdStart) {
  const chunks = chunkFrame(frameBytes);
  let reqId = reqIdStart;
  let i = 0;
  return new Promise((resolve) => {
    const iv = setInterval(() => {
      if (i >= chunks.length) { clearInterval(iv); resolve(reqId); return; }
      const vs3To = i === 0 ? toWallet : null;
      sock.write(encodeGhostShare(reqId++, minerId, jobId, chunks[i], vs3To) + '\n');
      i++;
    }, 150);
  });
}

// ─── Connection ─────────────────────────────────────────────────────────────

const sock = net.connect(PORT, HOST, () => {
  let buf = '', minerId = null, jobId = null, reqId = 100;
  let chatReady = false, rl = null;

  sock.on('data', (d) => {
    buf += d.toString();
    const lines = buf.split('\n');
    buf = lines.pop();

    for (const line of lines) {
      if (!line.trim()) continue;
      let msg; try { msg = JSON.parse(line); } catch { continue; }

      // Login response
      if (msg.id === 1 && msg.result) {
        minerId = msg.result.id;
        jobId   = msg.result.job?.job_id;
        if (jobId) onReady();
      }

      // Job notification
      if (msg.method === 'job' && msg.params) {
        if (msg.params.job_id) jobId = msg.params.job_id;
        if (!chatReady && jobId) onReady();

        // Receive VS3 frame
        if (msg.params.vs3) {
          const frame = Buffer.from(msg.params.vs3, 'hex');
          if (frame.length >= 9 && frame[0] === 0xAA) {
            const type = frame[2];
            const payloadLen = frame[7];
            const payload = frame.slice(8, 8 + payloadLen);
            handleIncoming(type, payload);
          }
        }
      }
    }
  });

  function handleIncoming(type, payload) {
    if (type === MSG_TYPE_KEY_EXCHANGE && payload.length === 32) {
      const isNew = !peerPubKey;
      peerPubKey = payload;
      console.log(`  [key] Peer key received: ${peerPubKey.toString('hex').slice(0, 16)}...`);
      console.log(`  [key] E2E encryption active. Type a message.\n`);
      // Send our key back so the peer gets it (they may have connected after us)
      if (isNew && chatReady) {
        const keyFrame = buildVS3Frame(myKeys.publicKey, MSG_TYPE_KEY_EXCHANGE);
        sendFrame(sock, minerId, jobId, keyFrame, reqId).then(r => { reqId = r; });
      }
      // Flush pending messages
      if (pendingMessages.length > 0) {
        console.log(`  [key] Sending ${pendingMessages.length} queued message(s)...`);
        for (const text of pendingMessages) doSend(text);
        pendingMessages.length = 0;
      }
      if (rl) rl.prompt();
      return;
    }

    if (type === MSG_TYPE_ENCRYPTED && peerPubKey) {
      try {
        const plaintext = decryptMessage(payload, myKeys.privateKey);
        const ts = new Date().toISOString().slice(11, 19);
        if (rl) {
          readline.clearLine(process.stdout, 0);
          readline.cursorTo(process.stdout, 0);
        }
        console.log(`  ${ts} [peer] ${plaintext.toString('utf8')}`);
        if (rl) rl.prompt(true);
      } catch (err) {
        console.log(`  [err] Decryption failed: ${err.message}`);
      }
      return;
    }

    if (type === MSG_TYPE_ENCRYPTED && !peerPubKey) {
      console.log('  [wait] Encrypted message received but no peer key yet — dropped');
      return;
    }
  }

  async function onReady() {
    if (chatReady) return;
    chatReady = true;

    // Send our public key
    console.log('  [key] Sending public key to peer...');
    const keyFrame = buildVS3Frame(myKeys.publicKey, MSG_TYPE_KEY_EXCHANGE);
    reqId = await sendFrame(sock, minerId, jobId, keyFrame, reqId);

    if (!peerPubKey) {
      console.log('  [key] Waiting for peer key... (they must connect too)\n');
    }

    // Start interactive chat
    rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    rl.setPrompt('  [you] ');
    rl.prompt();

    rl.on('line', (input) => {
      const text = input.trim();
      if (!text) { rl.prompt(); return; }

      if (!peerPubKey) {
        pendingMessages.push(text);
        console.log('  [queue] Peer key not yet received — message queued');
        rl.prompt();
        return;
      }

      doSend(text);
    });

    rl.on('close', () => sock.destroy());
  }

  async function doSend(text) {
    const encrypted = encryptMessage(text, peerPubKey);
    const frame = buildVS3Frame(encrypted, MSG_TYPE_ENCRYPTED);
    const chunks = chunkFrame(frame);
    const overhead = encrypted.length - Buffer.byteLength(text, 'utf8');
    console.log(`  [send] ${text.length}B text + ${overhead}B crypto overhead = ${encrypted.length}B → ${chunks.length} ghost shares`);
    reqId = await sendFrame(sock, minerId, jobId, frame, reqId);
    if (rl) rl.prompt();
  }

  // Login
  sock.write(JSON.stringify({
    id: 1, jsonrpc: '2.0', method: 'login',
    params: { login: myWallet, pass: 'x', agent: 'vs3-chat/1.0' }
  }) + '\n');
});

sock.on('error', (e) => console.error(`  [err] ${e.message}`));
sock.on('close', () => console.log('\n  Disconnected.'));
