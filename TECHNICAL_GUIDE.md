# Technical Guide — VS3 Pool Demo

This document is for technically qualified readers who want to understand the pool demo code (`src/stratum-demo.js`). For the proxy and V1/V2 steganography, see [`poc/README.md`](poc/README.md).

---

## What This Code Is

`src/stratum-demo.js` is a minimal but complete XMRig-compatible Stratum server (~730 lines, zero dependencies) that implements VS3 ghost share detection, frame reassembly, and bidirectional message delivery. It demonstrates a **VS3-aware pool** — the alternative deployment model to the proxy (see `poc/`).

This is NOT a production pool. It is a proof-of-concept that demonstrates the VS3 transport mechanism in isolation. Encryption, TLS, and Mining Gate are implemented in the [reference implementation](https://github.com/tnzx-project/tnzx-protocol/tree/main/reference-impl) and are not wired into this demo.

---

## Ghost Share Detection

**Function:** `_submit()`, line ~406.

```js
if (nonce.startsWith('aa') && miner.difficulty <= CFG.ghostDiffMax) {
```

Two conditions must both be true:
- `nonce.startsWith('aa')`: the sentinel byte 0xAA signals a ghost share
- `miner.difficulty <= CFG.ghostDiffMax` (default 500): prevents misrouting real high-difficulty shares that coincidentally start with 0xAA (probability 1/256)

Both code paths return `{"status":"OK"}` — indistinguishable to an observer.

## Payload Extraction (5 bytes/share)

**Function:** `_handleGhostShare()`, line ~446.

```js
const nb = Buffer.from((params.nonce || '').padStart(8,'0'), 'hex');
const tb = Buffer.from((params.ntime || '').padStart(8,'0'), 'hex');
const payload = Buffer.concat([nb.slice(1,4), tb.slice(2,4)]); // 5 bytes
```

| Field | Example | Payload bytes |
|-------|---------|---------------|
| nonce | `aa4865c3` | `[48, 65, C3]` (3 bytes from nonce[1..3]) |
| ntime | `65f36c6f` | `[6C, 6F]` (2 bytes from ntime[2..3]) |

The ntime high word preserves the real Unix epoch, keeping it within the pool's acceptance window.

**Protocol note:** `ntime` is a TNZX extension to Monero Stratum. Standard XMRig does not send this field. Ghost shares require a VS-enhanced miner (e.g., vs-miner) or a VS3 proxy.

## Frame Format

| Offset | Field | Size | Description |
|--------|-------|------|-------------|
| 0 | MAGIC | 1 | Always 0xAA |
| 1 | version | 1 | 0x03 = VS3 |
| 2 | type | 1 | 0x01=text, 0x02=ack, 0x03=ping |
| 3-4 | message_id | 2 | Big-endian |
| 5 | fragment_index | 1 | 0-based |
| 6 | fragment_total | 1 | 1 = no fragmentation |
| 7 | payload_len | 1 | N bytes |
| 8..8+N | payload | N | Content |

Example: "Hello" (5 bytes) → 13-byte frame → 3 ghost shares.

## Message Routing

**Function:** `routeVS3()`, line ~602.

The recipient is identified by wallet address in the `vs3_to` field of the first ghost share. The pool injects the assembled frame into the recipient's next job notification as a hex-encoded `vs3` field — an unrecognized extension field that standard XMRig ignores.

## Running

```bash
# Start the pool demo (no Monero daemon required)
node src/stratum-demo.js

# Test ghost share upload
node test-ghost.js 127.0.0.1 4444

# Bidirectional chat (3 terminals)
# T1: node src/stratum-demo.js
# T2: node vs3-client.js listen <bob_wallet>
# T3: node vs3-client.js send <alice_wallet> <bob_wallet> "message"
```

## Limitations

- **No encryption.** Frames travel in plaintext. Production uses X25519 + XChaCha20-Poly1305.
- **No TLS.** Demo uses plaintext TCP for readability.
- **No Mining Gate.** The pool demo does not enforce PoW gating (the proxy does).
- **The 0xAA sentinel is detectable** given enough traffic. A hardened version would use a session-negotiated marker.
- **Throughput is low by design.** ~300 bytes/min at 1 share/sec. Designed for short messages, not bulk transfer.
- **Pool is trusted.** A malicious pool can read/drop frames. E2E encryption mitigates the read risk.

## Planned Extensions

| ID | Description |
|----|-------------|
| SPEC-01 | VS3-Generic profile (extranonce2, 7 bytes/share) |
| EDGE-01 | Multi-fragment concurrency from same sender |
| EDGE-02 | Duplicate wallet login detection |

---

## License

LGPL-2.1
