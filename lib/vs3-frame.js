'use strict';
/**
 * VS3 Frame encoding utilities — shared across POC, tests, and demo
 *
 * Frame format (8-byte header + N-byte payload):
 *   [0] magic     0xAA
 *   [1] version   0x03
 *   [2] type      MSG_TYPE enum
 *   [3-4] msg_id  16-bit big-endian (random per message)
 *   [5] frag_idx  0-based fragment number
 *   [6] frag_tot  total fragments (1 = no fragmentation)
 *   [7] len       payload byte length
 *   [8..] payload
 *
 * Ghost share encoding (5 bytes per share):
 *   nonce  = 0xAA | payload[0..2]  (sentinel + 3 bytes)
 *   ntime  = epoch_hi | payload[3..4]  (real timestamp high + 2 payload bytes)
 *
 * @license LGPL-2.1
 */

const crypto = require('crypto');

/**
 * Build a single-fragment VS3 frame with random message_id
 * @param {Buffer|string} payload - Frame payload (max 247 bytes for single fragment)
 * @param {number} [msgType=0x01] - Message type (0x01=TEXT, 0x04=KEY_EXCHANGE, 0x05=ENCRYPTED)
 * @returns {Buffer} Complete VS3 frame (header + payload)
 */
function buildVS3Frame(payload, msgType = 0x01) {
  const buf = Buffer.isBuffer(payload)
    ? payload.slice(0, 247)
    : Buffer.from(payload, 'utf8').slice(0, 247);
  const msgId = crypto.randomBytes(2).readUInt16BE(0);
  return Buffer.concat([
    Buffer.from([0xAA, 0x03, msgType, (msgId >> 8) & 0xFF, msgId & 0xFF, 0x00, 0x01, buf.length]),
    buf
  ]);
}

/**
 * Split a VS3 frame into 5-byte chunks for ghost share encoding
 * @param {Buffer} frameBytes - Complete VS3 frame
 * @param {number} [bytesPerChunk=5] - Bytes per ghost share (5 for Monero, 7 for Bitcoin)
 * @returns {Buffer[]} Array of zero-padded chunks
 */
function chunkFrame(frameBytes, bytesPerChunk = 5) {
  const chunks = [];
  for (let i = 0; i < frameBytes.length; i += bytesPerChunk) {
    const c = Buffer.alloc(bytesPerChunk, 0);
    frameBytes.copy(c, 0, i, Math.min(i + bytesPerChunk, frameBytes.length));
    chunks.push(c);
  }
  return chunks;
}

/**
 * Encode a 5-byte chunk as a Monero Stratum ghost share submit
 * @param {number} reqId - JSON-RPC request id
 * @param {string} minerId - Miner session id
 * @param {string} jobId - Current job id
 * @param {Buffer} chunk - Exactly 5 bytes of frame payload
 * @param {string|null} vs3To - Recipient wallet (only on first share)
 * @returns {string} JSON-RPC submit message
 */
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

module.exports = { buildVS3Frame, chunkFrame, encodeGhostShare };
