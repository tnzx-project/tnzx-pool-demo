'use strict';
/**
 * @deprecated Use @tnzx/sdk (packages/sdk/lib/crypto/e2e.js) instead.
 * This module uses a DIFFERENT wire format (no replayId, different AAD)
 * and is NOT compatible with the SDK. It remains here only for the
 * existing demo scripts. New code should use the SDK.
 *
 * E2E Encryption for VS3 Demo — X25519 ECDH + XChaCha20-Poly1305
 *
 * Minimal wrapper around the reference implementation crypto.
 * Provides one-shot encryption with Perfect Forward Secrecy:
 * each message uses a fresh ephemeral X25519 keypair.
 *
 * Wire format (one-shot):
 *   ephemeralPub(32) || nonce(24) || ciphertext(N) || tag(16)
 *   Overhead: 72 bytes per message
 *
 * @license LGPL-2.1
 */

const crypto = require('crypto');
const xchacha = require('./xchacha20');

const KEY_LEN   = 32;
const NONCE_LEN = 24;
const TAG_LEN   = 16;
const EPH_LEN   = 32; // ephemeral X25519 public key

/**
 * Generate X25519 keypair
 * @returns {{ publicKey: Buffer, privateKey: Buffer }}
 */
function generateKeyPair() {
  const kp = crypto.generateKeyPairSync('x25519', {
    publicKeyEncoding:  { type: 'spki',  format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'der' }
  });
  return {
    publicKey:  kp.publicKey.slice(-32),
    privateKey: kp.privateKey.slice(-32)
  };
}

/**
 * X25519 Diffie-Hellman
 * @param {Buffer} myPrivate - 32-byte X25519 private key
 * @param {Buffer} theirPublic - 32-byte X25519 public key
 * @returns {Buffer} 32-byte shared secret
 */
function ecdh(myPrivate, theirPublic) {
  if (!Buffer.isBuffer(myPrivate) || myPrivate.length !== 32) throw new Error('Private key must be 32 bytes');
  if (!Buffer.isBuffer(theirPublic) || theirPublic.length !== 32) throw new Error('Public key must be 32 bytes');
  const priv = crypto.createPrivateKey({
    key: Buffer.concat([
      Buffer.from('302e020100300506032b656e04220420', 'hex'),
      myPrivate
    ]),
    format: 'der', type: 'pkcs8'
  });
  const pub = crypto.createPublicKey({
    key: Buffer.concat([
      Buffer.from('302a300506032b656e032100', 'hex'),
      theirPublic
    ]),
    format: 'der', type: 'spki'
  });
  return crypto.diffieHellman({ privateKey: priv, publicKey: pub });
}

/**
 * Derive encryption key via HKDF-SHA256
 */
function deriveKey(shared, salt) {
  return Buffer.from(crypto.hkdfSync('sha256', shared, salt, 'tnzx-e2e-demo-v1', KEY_LEN));
}

/**
 * Encrypt with PFS (one-shot: fresh ephemeral key per message)
 *
 * @param {Buffer|string} plaintext
 * @param {Buffer} recipientPub - 32-byte X25519 public key
 * @returns {Buffer} ephPub(32) || nonce(24) || ciphertext || tag(16)
 */
function encryptMessage(plaintext, recipientPub) {
  if (!Buffer.isBuffer(recipientPub) || recipientPub.length !== 32) throw new Error('recipientPub must be 32 bytes');
  const eph = generateKeyPair();
  const shared = ecdh(eph.privateKey, recipientPub);
  const salt = crypto.randomBytes(32);
  const key = deriveKey(shared, salt);
  const nonce = crypto.randomBytes(NONCE_LEN);

  const ptBuf = Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(plaintext, 'utf8');
  // AAD includes salt to prevent salt-substitution attacks (authenticated but not encrypted)
  const aad = Buffer.concat([Buffer.from('tnzx-demo-v1', 'utf8'), eph.publicKey, salt]);

  try {
    const { ciphertext, tag } = xchacha.encrypt(key, nonce, ptBuf, aad);
    return Buffer.concat([eph.publicKey, salt, nonce, ciphertext, tag]);
  } finally {
    key.fill(0);
    shared.fill(0);
    eph.privateKey.fill(0);
  }
}

/**
 * Decrypt one-shot message
 *
 * @param {Buffer} packet - ephPub(32) || salt(32) || nonce(24) || ciphertext || tag(16)
 * @param {Buffer} myPrivate - 32-byte X25519 private key
 * @returns {Buffer} plaintext
 */
function decryptMessage(packet, myPrivate) {
  const minLen = EPH_LEN + 32 + NONCE_LEN + TAG_LEN;
  if (packet.length < minLen) throw new Error('Packet too short');

  let off = 0;
  const ephPub = packet.slice(off, off + EPH_LEN); off += EPH_LEN;
  const salt   = packet.slice(off, off + 32);      off += 32;
  const nonce  = packet.slice(off, off + NONCE_LEN); off += NONCE_LEN;
  const tag    = packet.slice(-TAG_LEN);
  const ct     = packet.slice(off, -TAG_LEN);

  const shared = ecdh(myPrivate, ephPub);
  const key = deriveKey(shared, salt);
  // AAD must match encryption: includes salt for salt-substitution protection
  const aad = Buffer.concat([Buffer.from('tnzx-demo-v1', 'utf8'), ephPub, salt]);

  try {
    return xchacha.decrypt(key, nonce, ct, tag, aad);
  } finally {
    key.fill(0);
    shared.fill(0);
  }
}

module.exports = { generateKeyPair, encryptMessage, decryptMessage };
