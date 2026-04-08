'use strict';
/**
 * test-dpi-steganalysis.js — Statistical indistinguishability test for VS3
 *
 * Simulates a DPI adversary that observes Stratum nonce fields and tries to
 * distinguish normal mining traffic from traffic containing ghost shares.
 *
 * What this test proves:
 *   1. With HMAC sentinel, nonce[0] byte distribution is uniform (chi-squared)
 *   2. With legacy 0xAA sentinel, nonce[0] has an obvious spike at 0xAA
 *   3. Full 4-byte nonce distribution is uniform under both modes
 *   4. An adversary cannot distinguish HMAC ghost shares from real shares
 *      using first-order byte frequency analysis
 *   5. HMAC is resilient at ghost ratios from 5% to 50%
 *   6. Legacy 0xAA is detectable even at 5% ghost ratio
 *
 * What this test does NOT prove:
 *   - Second-order statistics: no test for sequential correlation between
 *     consecutive nonces (e.g., ghost shares tend to cluster in bursts).
 *   - Timing analysis: ghost shares may arrive at different intervals than
 *     real shares (real shares depend on PoW search time; ghost shares don't).
 *   - Cross-field correlation: an adversary who correlates nonce with the
 *     result field (ghost shares have result=0x00...00) can trivially detect
 *     ghost shares regardless of sentinel. This test only covers nonce bytes.
 *   - Real mining nonce distribution: test uses crypto.randomBytes() as
 *     "normal" nonces. Real mining nonces may have non-uniform patterns
 *     depending on the mining software (e.g., sequential search, per-thread
 *     partitioning). A production steganalysis should use captured traffic.
 *   - ntime field analysis: ghost shares encode payload in ntime low bytes,
 *     which may deviate from real timestamps. Not tested here.
 *
 * Methodology:
 *   - Generate N nonces (mix of real mining + ghost shares at ratio R)
 *   - Compute chi-squared statistic on byte distributions
 *   - Compare against critical value (p=0.05, df=255)
 *   - Report: PASS if chi-squared < critical (indistinguishable)
 *             FAIL if chi-squared >= critical (distinguishable)
 *
 * Run: node poc/test-dpi-steganalysis.js
 *
 * @license LGPL-2.1
 */

const crypto = require('crypto');
const { _hmac: { hmacDeriveKey, hmacSentinel } } = require('./vs3-proxy.js');

// ── Config ──────────────────────────────────────────────────────────────────

const SAMPLE_SIZE     = 50000;   // total nonces observed by DPI (50K for stable statistics)
const GHOST_RATIO     = 0.10;    // 10% ghost shares (realistic mining scenario)
const GHOST_COUNT     = Math.floor(SAMPLE_SIZE * GHOST_RATIO);
const REAL_COUNT      = SAMPLE_SIZE - GHOST_COUNT;

// Chi-squared critical value: df=255, p=0.01 → 310.46
// We use p=0.01 (not 0.05) because we run multiple tests on the same data.
// At p=0.01 with 4 byte positions, the chance of at least one false positive
// is ~4% (1 - 0.99^4), which is acceptable for a test suite.
const CHI_SQUARED_CRITICAL = 310.46;

let passed = 0;
let failed = 0;

function assert(condition, name) {
  if (condition) {
    passed++;
    console.log(`  \u2713 ${name}`);
  } else {
    failed++;
    console.error(`  \u2717 FAIL: ${name}`);
  }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

function chiSquared(observed, expected) {
  let sum = 0;
  for (let i = 0; i < observed.length; i++) {
    const diff = observed[i] - expected;
    sum += (diff * diff) / expected;
  }
  return sum;
}

function byteHistogram(nonces, byteIndex) {
  const counts = new Array(256).fill(0);
  for (const nonce of nonces) {
    counts[nonce[byteIndex]]++;
  }
  return counts;
}

function generateRealNonce() {
  return crypto.randomBytes(4);
}

function generateGhostNonce_Legacy(payload3bytes) {
  // Legacy: nonce[0] = 0xAA, nonce[1..3] = payload
  return Buffer.from([0xAA, payload3bytes[0], payload3bytes[1], payload3bytes[2]]);
}

function generateGhostNonce_HMAC(sessionKey, payload3bytes) {
  // HMAC: nonce[0] = HMAC sentinel, nonce[1..3] = payload
  const tag = hmacSentinel(sessionKey, payload3bytes);
  return Buffer.from([tag, payload3bytes[0], payload3bytes[1], payload3bytes[2]]);
}

// ── Test 1: Legacy 0xAA sentinel — nonce[0] distribution ────────────────────

console.log('\n\u2550\u2550\u2550 DPI Steganalysis — Statistical Distinguishability Tests \u2550\u2550\u2550\n');

console.log(`Config: ${SAMPLE_SIZE} nonces, ${(GHOST_RATIO * 100).toFixed(0)}% ghost share ratio`);
console.log(`Chi-squared critical value (df=255, p=0.05): ${CHI_SQUARED_CRITICAL}\n`);

console.log('Test 1: Legacy 0xAA sentinel — nonce[0] byte distribution');
{
  const nonces = [];
  for (let i = 0; i < REAL_COUNT; i++) nonces.push(generateRealNonce());
  for (let i = 0; i < GHOST_COUNT; i++) {
    nonces.push(generateGhostNonce_Legacy(crypto.randomBytes(3)));
  }
  // Shuffle to simulate interleaved traffic
  for (let i = nonces.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [nonces[i], nonces[j]] = [nonces[j], nonces[i]];
  }

  const hist = byteHistogram(nonces, 0);
  const expected = SAMPLE_SIZE / 256;
  const chi2 = chiSquared(hist, expected);
  const aaCount = hist[0xAA];
  const aaExpected = expected;

  console.log(`  Observed 0xAA count: ${aaCount} (expected uniform: ~${Math.round(aaExpected)})`);
  console.log(`  0xAA excess: +${aaCount - Math.round(aaExpected)} (ghost shares spike)`);
  console.log(`  Chi-squared: ${chi2.toFixed(1)} (critical: ${CHI_SQUARED_CRITICAL})`);
  assert(chi2 >= CHI_SQUARED_CRITICAL, 'Legacy 0xAA IS distinguishable (expected: chi2 above critical)');
}

// ── Test 2: HMAC sentinel — nonce[0] byte distribution ──────────────────────

console.log('\nTest 2: HMAC sentinel — nonce[0] byte distribution');
{
  // Simulate multiple miners with different session keys
  const minerKeys = [];
  for (let i = 0; i < 20; i++) {
    const pass = `miner-${i}`;
    const salt = 'pool-session-2026';
    minerKeys.push(hmacDeriveKey(pass, salt));
  }

  const nonces = [];
  for (let i = 0; i < REAL_COUNT; i++) nonces.push(generateRealNonce());
  for (let i = 0; i < GHOST_COUNT; i++) {
    const key = minerKeys[i % minerKeys.length];
    const payload = crypto.randomBytes(3);
    nonces.push(generateGhostNonce_HMAC(key, payload));
  }
  for (let i = nonces.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [nonces[i], nonces[j]] = [nonces[j], nonces[i]];
  }

  const hist = byteHistogram(nonces, 0);
  const expected = SAMPLE_SIZE / 256;
  const chi2 = chiSquared(hist, expected);
  const aaCount = hist[0xAA];

  console.log(`  Observed 0xAA count: ${aaCount} (expected uniform: ~${Math.round(expected)})`);
  console.log(`  Chi-squared: ${chi2.toFixed(1)} (critical: ${CHI_SQUARED_CRITICAL})`);
  assert(chi2 < CHI_SQUARED_CRITICAL, 'HMAC sentinel is NOT distinguishable (chi2 below critical)');
}

// ── Test 3: HMAC — full nonce byte distribution (all 4 bytes) ───────────────

console.log('\nTest 3: HMAC sentinel — all nonce bytes uniform');
{
  const key = hmacDeriveKey('miner-test', 'pool-salt');
  const nonces = [];
  for (let i = 0; i < REAL_COUNT; i++) nonces.push(generateRealNonce());
  for (let i = 0; i < GHOST_COUNT; i++) {
    nonces.push(generateGhostNonce_HMAC(key, crypto.randomBytes(3)));
  }

  for (let byte = 0; byte < 4; byte++) {
    const hist = byteHistogram(nonces, byte);
    const expected = SAMPLE_SIZE / 256;
    const chi2 = chiSquared(hist, expected);
    assert(chi2 < CHI_SQUARED_CRITICAL, `nonce[${byte}] uniform (chi2=${chi2.toFixed(1)})`);
  }
}

// ── Test 4: Legacy — byte 1..3 are still uniform ────────────────────────────

console.log('\nTest 4: Legacy 0xAA — payload bytes [1..3] still uniform');
{
  const nonces = [];
  for (let i = 0; i < REAL_COUNT; i++) nonces.push(generateRealNonce());
  for (let i = 0; i < GHOST_COUNT; i++) {
    nonces.push(generateGhostNonce_Legacy(crypto.randomBytes(3)));
  }

  for (let byte = 1; byte < 4; byte++) {
    const hist = byteHistogram(nonces, byte);
    const expected = SAMPLE_SIZE / 256;
    const chi2 = chiSquared(hist, expected);
    assert(chi2 < CHI_SQUARED_CRITICAL, `nonce[${byte}] uniform (chi2=${chi2.toFixed(1)})`);
  }
}

// ── Test 5: Increasing ghost ratio — HMAC stays indistinguishable ───────────

console.log('\nTest 5: HMAC resilience at increasing ghost ratios');
{
  const key = hmacDeriveKey('stress-test', 'salt-2026');
  for (const ratio of [0.05, 0.10, 0.25, 0.50]) {
    const gCount = Math.floor(SAMPLE_SIZE * ratio);
    const rCount = SAMPLE_SIZE - gCount;
    const nonces = [];
    for (let i = 0; i < rCount; i++) nonces.push(generateRealNonce());
    for (let i = 0; i < gCount; i++) {
      nonces.push(generateGhostNonce_HMAC(key, crypto.randomBytes(3)));
    }
    const hist = byteHistogram(nonces, 0);
    const expected = SAMPLE_SIZE / 256;
    const chi2 = chiSquared(hist, expected);
    assert(chi2 < CHI_SQUARED_CRITICAL,
      `${(ratio * 100).toFixed(0)}% ghost: indistinguishable (chi2=${chi2.toFixed(1)})`);
  }
}

// ── Test 6: Legacy is distinguishable even at low ratios ────────────────────

console.log('\nTest 6: Legacy 0xAA distinguishable even at 5% ghost ratio');
{
  const gCount = Math.floor(SAMPLE_SIZE * 0.05);
  const rCount = SAMPLE_SIZE - gCount;
  const nonces = [];
  for (let i = 0; i < rCount; i++) nonces.push(generateRealNonce());
  for (let i = 0; i < gCount; i++) {
    nonces.push(generateGhostNonce_Legacy(crypto.randomBytes(3)));
  }
  const hist = byteHistogram(nonces, 0);
  const expected = SAMPLE_SIZE / 256;
  const chi2 = chiSquared(hist, expected);
  const aaExcess = hist[0xAA] - Math.round(expected);
  console.log(`  0xAA excess at 5%: +${aaExcess} (${hist[0xAA]} vs ~${Math.round(expected)} expected)`);
  console.log(`  Chi-squared: ${chi2.toFixed(1)}`);
  assert(chi2 >= CHI_SQUARED_CRITICAL, 'Legacy 0xAA detectable even at 5% ratio');
}

// ── Summary ─────────────────────────────────────────────────────────────────

console.log(`\n\u2550\u2550\u2550 Results: ${passed} passed, ${failed} failed \u2550\u2550\u2550\n`);

if (failed === 0) {
  console.log('DPI steganalysis validated:');
  console.log('  - Legacy 0xAA sentinel: DETECTABLE by first-order byte frequency analysis');
  console.log('  - HMAC rotating sentinel: INDISTINGUISHABLE from uniform random nonces');
  console.log('  - HMAC resilient up to 50% ghost share ratio');
  console.log('');
} else {
  console.log('SOME TESTS FAILED — review results above.');
}

process.exit(failed > 0 ? 1 : 0);
