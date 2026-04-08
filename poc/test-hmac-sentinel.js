'use strict';
/**
 * test-hmac-sentinel.js — Unit test for HMAC Rotating Sentinel (Appendix D)
 *
 * What this test proves:
 *   1. hmacDeriveKey produces a deterministic 32-byte key from (password, salt)
 *   2. hmacSentinel produces a valid single-byte tag from session key + nonce data
 *   3. hmacVerify correctly detects HMAC-tagged ghost shares
 *   4. hmacVerify rejects tampered, wrong-key, short, and null nonces
 *   5. Generated sentinel bytes are diverse (not fixed 0xAA) — DPI resistance
 *   6. Cross-miner isolation: Alice and Bob cannot forge each other's sentinels
 *
 * What this test does NOT prove:
 *   - Integration with the proxy: these are unit tests on exported functions,
 *     not end-to-end tests through the VS3Proxy class with HMAC enabled.
 *   - False positive rate under adversarial input: the 1/256 FP rate is
 *     theoretical. No test generates adversarial nonces designed to collide.
 *   - HKDF correctness against known test vectors (trusts Node.js crypto).
 *   - Timing safety of hmacVerify under adversarial observation (uses
 *     crypto.timingSafeEqual, but no timing measurement in this test).
 *   - Key rotation: no test for what happens when the pool salt changes
 *     mid-session or when miners reconnect with a new session key.
 *
 * @license LGPL-2.1
 */

const crypto = require('crypto');
const { _hmac: { hmacDeriveKey, hmacSentinel, hmacVerify } } = require('./vs3-proxy.js');

let passed = 0;
let failed = 0;

function assert(condition, name) {
  if (condition) {
    passed++;
    console.log(`  ✓ ${name}`);
  } else {
    failed++;
    console.error(`  ✗ FAIL: ${name}`);
  }
}

console.log('\n═══ HMAC Rotating Sentinel — Appendix D Validation ═══\n');

// ── Test 1: Key derivation is deterministic ─────────────────────────────────

console.log('Test 1: Key derivation');
const key1 = hmacDeriveKey('miner-password-123', 'pool-salt-abc');
const key2 = hmacDeriveKey('miner-password-123', 'pool-salt-abc');
assert(key1.length === 32, 'Key is 32 bytes');
assert(Buffer.compare(key1, key2) === 0, 'Same inputs → same key (deterministic)');

const key3 = hmacDeriveKey('different-password', 'pool-salt-abc');
assert(Buffer.compare(key1, key3) !== 0, 'Different password → different key');

const key4 = hmacDeriveKey('miner-password-123', 'different-salt');
assert(Buffer.compare(key1, key4) !== 0, 'Different salt → different key');

// ── Test 2: Sentinel generation ─────────────────────────────────────────────

console.log('\nTest 2: Sentinel generation');
const sessionKey = hmacDeriveKey('alice-pass', 'test-salt-2026');
const nonceData = Buffer.from([0x48, 0x65, 0x6C]); // "Hel" — 3 payload bytes
const sentinel = hmacSentinel(sessionKey, nonceData);
assert(typeof sentinel === 'number', 'Sentinel is a number');
assert(sentinel >= 0 && sentinel <= 255, 'Sentinel is in byte range [0, 255]');

// Same input → same sentinel
const sentinel2 = hmacSentinel(sessionKey, nonceData);
assert(sentinel === sentinel2, 'Same inputs → same sentinel (deterministic)');

// Different nonce data → different sentinel (with high probability)
const sentinel3 = hmacSentinel(sessionKey, Buffer.from([0x01, 0x02, 0x03]));
// Note: Could theoretically be equal (1/256 chance), but very unlikely
console.log(`  Sentinel for [48,65,6C]: 0x${sentinel.toString(16).padStart(2, '0')}`);
console.log(`  Sentinel for [01,02,03]: 0x${sentinel3.toString(16).padStart(2, '0')}`);

// ── Test 3: Verify detects HMAC-tagged ghost shares ─────────────────────────

console.log('\nTest 3: Verification');
// Build a valid HMAC-tagged nonce: nonce[0] = sentinel, nonce[1..3] = payload
const payloadBytes = Buffer.from([0x48, 0x65, 0x6C]);
const tag = hmacSentinel(sessionKey, payloadBytes);
const validNonce = Buffer.from([tag, ...payloadBytes]);
assert(hmacVerify(sessionKey, validNonce) === true, 'Valid HMAC ghost share detected');

// Tamper with the tag
const tamperedNonce = Buffer.from([tag ^ 0xFF, ...payloadBytes]);
assert(hmacVerify(sessionKey, tamperedNonce) === false, 'Tampered nonce rejected');

// Wrong session key
const wrongKey = hmacDeriveKey('wrong-password', 'test-salt-2026');
assert(hmacVerify(wrongKey, validNonce) === false, 'Wrong session key rejected');

// Too short nonce
assert(hmacVerify(sessionKey, Buffer.from([0x01, 0x02])) === false, 'Short nonce rejected');
assert(hmacVerify(sessionKey, null) === false, 'Null nonce rejected');

// ── Test 4: Diversity — sentinels are not fixed 0xAA ────────────────────────

console.log('\nTest 4: Sentinel diversity (DPI resistance)');
const sentinels = new Set();
let countAA = 0;
const SAMPLES = 100;

for (let i = 0; i < SAMPLES; i++) {
  const payload = crypto.randomBytes(3);
  const s = hmacSentinel(sessionKey, payload);
  sentinels.add(s);
  if (s === 0xAA) countAA++;
}

console.log(`  Unique sentinel values over ${SAMPLES} samples: ${sentinels.size}`);
console.log(`  Sentinels equal to 0xAA: ${countAA}/${SAMPLES}`);
assert(sentinels.size > 10, `Sufficient diversity: ${sentinels.size} unique values (expected >10)`);
// With 100 random payloads and HMAC, we expect ~100/256 ≈ 39 unique values minimum
// 0xAA appearing is ~100/256 ≈ 0.39 expected — usually 0 or 1
assert(countAA <= 5, `0xAA appearances acceptable: ${countAA} (expected ≤5 in 100 samples)`);

// ── Test 5: Cross-miner isolation ───────────────────────────────────────────

console.log('\nTest 5: Cross-miner isolation');
const aliceKey = hmacDeriveKey('alice-pass', 'test-salt-2026');
const bobKey   = hmacDeriveKey('bob-pass', 'test-salt-2026');

const sharedPayload = Buffer.from([0x48, 0x65, 0x6C]);
const aliceTag = hmacSentinel(aliceKey, sharedPayload);
const bobTag   = hmacSentinel(bobKey, sharedPayload);

// Alice's ghost share is not detected with Bob's key
const aliceNonce = Buffer.from([aliceTag, ...sharedPayload]);
assert(hmacVerify(aliceKey, aliceNonce) === true,  'Alice verifies her own shares');
assert(hmacVerify(bobKey, aliceNonce) === false,    'Bob cannot forge Alice\'s sentinel');

// Bob's ghost share is not detected with Alice's key
const bobNonce = Buffer.from([bobTag, ...sharedPayload]);
assert(hmacVerify(bobKey, bobNonce) === true,       'Bob verifies his own shares');
assert(hmacVerify(aliceKey, bobNonce) === false,     'Alice cannot forge Bob\'s sentinel');

// ── Summary ─────────────────────────────────────────────────────────────────

console.log(`\n═══ Results: ${passed} passed, ${failed} failed ═══\n`);

if (failed > 0) {
  console.error('HMAC sentinel validation FAILED');
  process.exit(1);
}
console.log('HMAC sentinel (Appendix D) validated successfully.');
console.log('DPI resistance confirmed: sentinel bytes are diverse, not fixed 0xAA.');
