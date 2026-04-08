/**
 * XChaCha20-Poly1305 — TNZX vendored implementation
 *
 * VENDORING NOTE: This file is an exact copy of
 * tnzx-protocol/reference-impl/crypto/xchacha20.js
 * Vendored here to keep the pool demo self-contained (zero cross-repo deps).
 *
 * HChaCha20 core derived from @noble/ciphers by Paul Miller (@paulmillr)
 * Original: https://github.com/paulmillr/noble-ciphers
 * License: MIT (Copyright (c) 2022 Paul Miller)
 * Audit: Cure53, 2023 — https://cure53.de/audit-report_noble-ciphers.pdf
 *
 * We vendorize only HChaCha20 (~40 lines of pure ARX). The actual
 * ChaCha20-Poly1305 AEAD uses Node.js native crypto (OpenSSL).
 *
 * XChaCha20-Poly1305 construction (draft-irtf-cfrg-xchacha):
 *   subkey    = HChaCha20(key, nonce[0:16])
 *   chacha_iv = 0x00000000 || nonce[16:24]
 *   result    = ChaCha20-Poly1305(subkey, chacha_iv, plaintext, aad)
 *
 * Thank you Paul Miller for your exceptional work on the noble cryptography
 * libraries. Your commitment to audited, constant-time, zero-dependency
 * JavaScript cryptography benefits the entire ecosystem.
 *
 * @module
 */

'use strict';

const crypto = require('crypto');

// ============================================================================
// HChaCha20 — derives 256-bit subkey from 256-bit key + 128-bit nonce
// Reference: draft-irtf-cfrg-xchacha, Section 2.2
// Pure ARX (add-rotate-xor), constant-time by construction.
// Derived from @noble/ciphers chacha.ts (MIT, Paul Miller)
// ============================================================================

/**
 * HChaCha20 subkey derivation.
 * @param {Buffer|Uint8Array} key - 32-byte key
 * @param {Buffer|Uint8Array} nonce16 - First 16 bytes of the 24-byte XChaCha20 nonce
 * @returns {Buffer} 32-byte subkey
 */
function hchacha20(key, nonce16) {
  if (key.length !== 32) throw new Error('hchacha20: key must be 32 bytes');
  if (nonce16.length !== 16) throw new Error('hchacha20: nonce must be 16 bytes');

  // Read key and nonce as little-endian uint32
  // Using DataView to avoid Buffer.buffer pool offset bug
  function readLE32(buf, offset) {
    return (buf[offset]) |
           (buf[offset + 1] << 8) |
           (buf[offset + 2] << 16) |
           (buf[offset + 3] << 24);
  }

  // ChaCha20 constants: "expand 32-byte k" as LE uint32
  let s0  = 0x61707865;
  let s1  = 0x3320646e;
  let s2  = 0x79622d32;
  let s3  = 0x6b206574;

  // Key words
  let s4  = readLE32(key, 0);
  let s5  = readLE32(key, 4);
  let s6  = readLE32(key, 8);
  let s7  = readLE32(key, 12);
  let s8  = readLE32(key, 16);
  let s9  = readLE32(key, 20);
  let s10 = readLE32(key, 24);
  let s11 = readLE32(key, 28);

  // Nonce words (replaces counter + nonce in standard ChaCha20)
  let s12 = readLE32(nonce16, 0);
  let s13 = readLE32(nonce16, 4);
  let s14 = readLE32(nonce16, 8);
  let s15 = readLE32(nonce16, 12);

  // 20 rounds (10 double-rounds: column + diagonal)
  for (let i = 0; i < 10; i++) {
    // Column round
    s0  = (s0  + s4)  | 0; s12 ^= s0;  s12 = (s12 << 16) | (s12 >>> 16);
    s8  = (s8  + s12) | 0; s4  ^= s8;  s4  = (s4  << 12) | (s4  >>> 20);
    s0  = (s0  + s4)  | 0; s12 ^= s0;  s12 = (s12 <<  8) | (s12 >>> 24);
    s8  = (s8  + s12) | 0; s4  ^= s8;  s4  = (s4  <<  7) | (s4  >>> 25);

    s1  = (s1  + s5)  | 0; s13 ^= s1;  s13 = (s13 << 16) | (s13 >>> 16);
    s9  = (s9  + s13) | 0; s5  ^= s9;  s5  = (s5  << 12) | (s5  >>> 20);
    s1  = (s1  + s5)  | 0; s13 ^= s1;  s13 = (s13 <<  8) | (s13 >>> 24);
    s9  = (s9  + s13) | 0; s5  ^= s9;  s5  = (s5  <<  7) | (s5  >>> 25);

    s2  = (s2  + s6)  | 0; s14 ^= s2;  s14 = (s14 << 16) | (s14 >>> 16);
    s10 = (s10 + s14) | 0; s6  ^= s10; s6  = (s6  << 12) | (s6  >>> 20);
    s2  = (s2  + s6)  | 0; s14 ^= s2;  s14 = (s14 <<  8) | (s14 >>> 24);
    s10 = (s10 + s14) | 0; s6  ^= s10; s6  = (s6  <<  7) | (s6  >>> 25);

    s3  = (s3  + s7)  | 0; s15 ^= s3;  s15 = (s15 << 16) | (s15 >>> 16);
    s11 = (s11 + s15) | 0; s7  ^= s11; s7  = (s7  << 12) | (s7  >>> 20);
    s3  = (s3  + s7)  | 0; s15 ^= s3;  s15 = (s15 <<  8) | (s15 >>> 24);
    s11 = (s11 + s15) | 0; s7  ^= s11; s7  = (s7  <<  7) | (s7  >>> 25);

    // Diagonal round
    s0  = (s0  + s5)  | 0; s15 ^= s0;  s15 = (s15 << 16) | (s15 >>> 16);
    s10 = (s10 + s15) | 0; s5  ^= s10; s5  = (s5  << 12) | (s5  >>> 20);
    s0  = (s0  + s5)  | 0; s15 ^= s0;  s15 = (s15 <<  8) | (s15 >>> 24);
    s10 = (s10 + s15) | 0; s5  ^= s10; s5  = (s5  <<  7) | (s5  >>> 25);

    s1  = (s1  + s6)  | 0; s12 ^= s1;  s12 = (s12 << 16) | (s12 >>> 16);
    s11 = (s11 + s12) | 0; s6  ^= s11; s6  = (s6  << 12) | (s6  >>> 20);
    s1  = (s1  + s6)  | 0; s12 ^= s1;  s12 = (s12 <<  8) | (s12 >>> 24);
    s11 = (s11 + s12) | 0; s6  ^= s11; s6  = (s6  <<  7) | (s6  >>> 25);

    s2  = (s2  + s7)  | 0; s13 ^= s2;  s13 = (s13 << 16) | (s13 >>> 16);
    s8  = (s8  + s13) | 0; s7  ^= s8;  s7  = (s7  << 12) | (s7  >>> 20);
    s2  = (s2  + s7)  | 0; s13 ^= s2;  s13 = (s13 <<  8) | (s13 >>> 24);
    s8  = (s8  + s13) | 0; s7  ^= s8;  s7  = (s7  <<  7) | (s7  >>> 25);

    s3  = (s3  + s4)  | 0; s14 ^= s3;  s14 = (s14 << 16) | (s14 >>> 16);
    s9  = (s9  + s14) | 0; s4  ^= s9;  s4  = (s4  << 12) | (s4  >>> 20);
    s3  = (s3  + s4)  | 0; s14 ^= s3;  s14 = (s14 <<  8) | (s14 >>> 24);
    s9  = (s9  + s14) | 0; s4  ^= s9;  s4  = (s4  <<  7) | (s4  >>> 25);
  }

  // HChaCha20 output: first and last row of state (NO addition of input state)
  // This differs from ChaCha20 which adds the input state back
  const out = Buffer.alloc(32);
  out.writeUInt32LE(s0  >>> 0, 0);
  out.writeUInt32LE(s1  >>> 0, 4);
  out.writeUInt32LE(s2  >>> 0, 8);
  out.writeUInt32LE(s3  >>> 0, 12);
  out.writeUInt32LE(s12 >>> 0, 16);
  out.writeUInt32LE(s13 >>> 0, 20);
  out.writeUInt32LE(s14 >>> 0, 24);
  out.writeUInt32LE(s15 >>> 0, 28);
  return out;
}

// ============================================================================
// XChaCha20-Poly1305 AEAD — HChaCha20 + native ChaCha20-Poly1305
// ============================================================================

const NONCE_LEN = 24;
const TAG_LEN = 16;

/**
 * Encrypt with XChaCha20-Poly1305.
 * @param {Buffer} key - 32-byte encryption key
 * @param {Buffer} nonce - 24-byte nonce (safe to generate randomly)
 * @param {Buffer} plaintext - Data to encrypt
 * @param {Buffer} [aad] - Optional additional authenticated data
 * @returns {{ ciphertext: Buffer, tag: Buffer, nonce: Buffer }}
 */
function encrypt(key, nonce, plaintext, aad) {
  if (key.length !== 32) throw new Error('xchacha20: key must be 32 bytes');
  if (nonce.length !== NONCE_LEN) throw new Error('xchacha20: nonce must be 24 bytes');

  // Step 1: derive subkey via HChaCha20
  const subkey = hchacha20(key, nonce.subarray(0, 16));

  try {
    // Step 2: build 12-byte nonce for ChaCha20-Poly1305
    // 4 zero bytes + last 8 bytes of original nonce
    const chachaNonce = Buffer.alloc(12);
    nonce.copy(chachaNonce, 4, 16, 24);

    // Step 3: encrypt with native ChaCha20-Poly1305
    const cipher = crypto.createCipheriv('chacha20-poly1305', subkey, chachaNonce, {
      authTagLength: TAG_LEN
    });
    if (aad && aad.length > 0) cipher.setAAD(aad);

    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();

    return { ciphertext, tag, nonce };
  } finally {
    // Wipe subkey from memory — even on exception
    subkey.fill(0);
  }
}

/**
 * Decrypt with XChaCha20-Poly1305.
 * @param {Buffer} key - 32-byte encryption key
 * @param {Buffer} nonce - 24-byte nonce
 * @param {Buffer} ciphertext - Data to decrypt
 * @param {Buffer} tag - 16-byte Poly1305 authentication tag
 * @param {Buffer} [aad] - Optional additional authenticated data
 * @returns {Buffer} Decrypted plaintext
 * @throws {Error} If authentication fails
 */
function decrypt(key, nonce, ciphertext, tag, aad) {
  if (key.length !== 32) throw new Error('xchacha20: key must be 32 bytes');
  if (nonce.length !== NONCE_LEN) throw new Error('xchacha20: nonce must be 24 bytes');
  if (tag.length !== TAG_LEN) throw new Error('xchacha20: tag must be 16 bytes');

  // Step 1: derive subkey via HChaCha20
  const subkey = hchacha20(key, nonce.subarray(0, 16));

  try {
    // Step 2: build 12-byte nonce
    const chachaNonce = Buffer.alloc(12);
    nonce.copy(chachaNonce, 4, 16, 24);

    // Step 3: decrypt with native ChaCha20-Poly1305
    const decipher = crypto.createDecipheriv('chacha20-poly1305', subkey, chachaNonce, {
      authTagLength: TAG_LEN
    });
    if (aad && aad.length > 0) decipher.setAAD(aad);
    decipher.setAuthTag(tag);

    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } finally {
    // Wipe subkey from memory — even on auth failure
    subkey.fill(0);
  }
}

/**
 * Encrypt and pack into wire format: nonce(24) || ciphertext || tag(16)
 * @param {Buffer} key - 32-byte key
 * @param {Buffer} plaintext - Data to encrypt
 * @param {Buffer} [aad] - Optional AAD
 * @returns {Buffer} Wire-format packet
 */
function seal(key, plaintext, aad) {
  const nonce = crypto.randomBytes(NONCE_LEN);
  const { ciphertext, tag } = encrypt(key, nonce, plaintext, aad);
  return Buffer.concat([nonce, ciphertext, tag]);
}

/**
 * Unpack wire format and decrypt: nonce(24) || ciphertext || tag(16)
 * @param {Buffer} key - 32-byte key
 * @param {Buffer} packet - Wire-format packet from seal()
 * @param {Buffer} [aad] - Optional AAD
 * @returns {Buffer} Decrypted plaintext
 * @throws {Error} If packet too short or authentication fails
 */
function open(key, packet, aad) {
  if (packet.length < NONCE_LEN + TAG_LEN) {
    throw new Error('xchacha20: packet too short');
  }
  const nonce = packet.subarray(0, NONCE_LEN);
  const ciphertext = packet.subarray(NONCE_LEN, packet.length - TAG_LEN);
  const tag = packet.subarray(packet.length - TAG_LEN);
  return decrypt(key, nonce, ciphertext, tag, aad);
}

// ============================================================================
// Exports
// ============================================================================

module.exports = {
  hchacha20,
  encrypt,
  decrypt,
  seal,
  open,
  NONCE_LEN,
  TAG_LEN,
};
