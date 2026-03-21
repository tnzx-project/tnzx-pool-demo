# Demo Reading Guide — TNZX VS3 Protocol POC

This document is written for technically qualified readers who want to
understand this proof-of-concept. It explains what the code demonstrates,
how to navigate it, and what it does not yet do.

---

## 1. Why This Protocol Exists

Standard censorship-resistance tools — Tor, VPNs, Signal — share a common
vulnerability: their traffic is structurally identifiable. TLS handshake
patterns, SNI leakage, flow timing, and port reputation give deep packet
inspection (DPI) systems enough signal to block or throttle them, even without
decrypting the content. In jurisdictions where network operators act as
instruments of state censorship, blocking is applied at the flow level, not
the content level.

TNZX VS3 ("Vector Steganography v3") hides arbitrary binary messages inside
Monero cryptocurrency mining traffic. A journalist, activist, or whistleblower
runs a modified mining client against a VS3-aware pool. To every passive
observer — including state-level DPI — the connection is indistinguishable
from normal Monero mining. The covert channel requires no new ports, no new
protocols, and no behavioral anomaly in the traffic stream.

Monero is a deliberate choice of carrier. It is CPU-mineable (RandomX), which
means it runs on ordinary laptops without specialized hardware. Mining traffic
originates from millions of devices worldwide. In production, Stratum
connections run over TLS — making the stream identical to HTTPS from the
network layer down. Blocking it requires blocking all Monero mining globally,
which carries substantial economic and political cost for the censor.

---

## 2. What This POC Demonstrates

This repository is a single-file Node.js Stratum server (~660 lines, no
external dependencies), plus `vs3-client.js` (~230 lines) — a bidirectional
VS3 client that lets two parties communicate through the pool.
It demonstrates two transport paths:

**Upload path (miner → pool):** A sender submits "ghost shares" — standard
Stratum `submit` messages whose `nonce` and `ntime` fields carry covert
payload bytes. The pool detects these shares, extracts the payload bytes, and
reassembles them into complete VS3 frames.

**Download path (pool → miner):** The pool injects reassembled VS3 frames into
outgoing job notifications as a hex-encoded extension field (`vs3`). A
VS3-aware recipient client reads this field; a standard XMRig client ignores it
without error.

**Indistinguishability claim:** The traffic produced is byte-for-byte
structurally identical to normal Stratum mining traffic. The `nonce` field
containing a covert payload is a valid JSON string of the correct length. The
`vs3` field in a job notification is an unrecognized extension field,
indistinguishable from any other pool-specific metadata (fee information, work
multipliers, etc.). No timing anomaly, no extra TCP connection, no unusual
packet size distribution.

This POC does **not** include encryption. Frames are transmitted as plaintext
to make the transport mechanism auditable without additional decryption tooling.
Encryption (X25519 key agreement + AES-256-GCM AEAD, HKDF-SHA256 key
derivation) is a separate layer implemented in `StratumMessengerEngine`,
not included in this repository.

---

## 3. How to Read the Code

All logic is in `src/stratum-demo.js`. The file has an extensive header comment
(lines 1–144) explaining the encoding scheme and frame format, followed by configuration and protocol constants (lines 151–224). Read that first.
The code walkthrough below references specific locations.

### 3.1 Ghost Share Detection

**Function:** `_submit()`, lines 390–426.
**Key condition:** line 415.

```js
if (nonce.startsWith('aa') && miner.difficulty <= CFG.ghostDiffMax) {
```

Two conditions must both be true:

- `nonce.startsWith('aa')`: the first byte of the nonce is `0xAA`, the VS3
  sentinel. This is checked as a hex string comparison on the raw Stratum
  field, requiring no binary parsing.
- `miner.difficulty <= CFG.ghostDiffMax` (default 500): limits ghost share
  detection to low-difficulty sessions. A real miner solving a high-difficulty
  share has a 1/256 probability of producing a nonce starting with `0xAA`;
  this condition prevents that share from being misrouted.

Both code paths (ghost share and real share) return `{"status":"OK"}` to the
sender. A passive observer cannot distinguish the two acknowledgments.

### 3.2 Extraction of the 5 Payload Bytes

**Function:** `_handleGhostShare()`, lines 428–604.
**Key line:** 460.

```js
const nb = Buffer.from((params.nonce || '').padStart(8,'0'), 'hex');
const tb = Buffer.from((params.ntime || '').padStart(8,'0'), 'hex');
const payload = Buffer.concat([nb.slice(1,4), tb.slice(2,4)]); // 5 bytes
```

Decoding, concretely:

| Field  | Hex string example | Decoded bytes        | Payload bytes extracted |
|--------|--------------------|----------------------|-------------------------|
| nonce  | `aa4865c3`         | `[AA, 48, 65, C3]`   | `nb[1..3]` = `[48,65,C3]` (3 bytes) |
| ntime  | `65f36c6f`         | `[65, F3, 6C, 6F]`   | `tb[2..3]` = `[6C,6F]` (2 bytes) |

Combined payload for this share: `[0x48, 0x65, 0xC3, 0x6C, 0x6F]`.

The `ntime` high word (`tb[0..1]`) is preserved as a real Unix epoch fragment
(epoch >> 16), keeping the timestamp within the ±7200-second acceptance window
that pools enforce for NTP drift tolerance. Only the low 16 bits are
overwritten with payload data, contributing at most ~18 hours of apparent drift
— well inside the acceptance window.

5 bytes/share is the maximum extractable from these two fields without touching
any other Stratum field. At 1 ghost share per second (achievable on any hardware
that can open a TCP connection), throughput is ~300 bytes/minute — sufficient
for text messages and compressed key material (a Signal key bundle is ~200
bytes).

### 3.3 Frame Parser

**Function:** `_handleGhostShare()`, lines 497–603 (the `while` loop).
**Frame format constants:** lines 223–224 (`GHOST_MAGIC = 0xAA`, `GHOST_HEADER = 8`).

The VS3 frame format (documented in detail at lines 108–143):

| Offset | Field          | Size | Notes                                      |
|--------|----------------|------|--------------------------------------------|
| 0      | MAGIC          | 1    | Always `0xAA` — frame boundary marker      |
| 1      | version        | 1    | Protocol version (`0x03` = VS3)            |
| 2      | type           | 1    | `0x01`=text, `0x02`=ack, `0x03`=ping (pool passes all types through; this POC client uses `0x01` only — ACK/ping are application-layer concerns) |
| 3–4    | message_id     | 2    | Logical message ID, big-endian             |
| 5      | fragment_index | 1    | Which fragment (0-based)                   |
| 6      | fragment_total | 1    | Total fragments (1 = no fragmentation)     |
| 7      | payload_len    | 1    | Byte length N of the payload that follows  |
| 8..8+N | payload       | N    | Content (UTF-8 text or binary)             |

Total frame size = `GHOST_HEADER + frame[7]` = `8 + N` bytes.

The parser loop is greedy: it accumulates payload bytes in `miner.ghostBuffer`
(a per-connection `Buffer`) and consumes complete frames from the front. A
partial frame tail remains in the buffer until subsequent ghost shares deliver
the remaining bytes. Re-synchronization on magic byte is handled at line 505
for the case where buffer misalignment occurs (e.g. after the overflow reset at
line 487).

The 4 KB overflow guard (line 487) caps per-connection memory usage and
prevents a trivial denial-of-service via malformed ghost share streams.

### 3.4 Frame Routing to the Recipient

**Function:** `routeVS3()`, lines 622–635.

```js
routeVS3(recipientWallet, frame) {
  for (const [,m] of this.miners) {
    if (m.wallet === recipientWallet && m.authorized) {
      m.pendingFrames = m.pendingFrames || [];
      m.pendingFrames.push(frame);
      // Immediately push a job notification so the frame is delivered
      // without waiting for the next block template update.
      this._sendJob(m);
      return true;
    }
  }
  return false;
}
```

The recipient is identified by their Monero wallet address, declared by the
sender in the `vs3_to` field of the first ghost share's params (lines 473–474).
This is a Stratum extension field: pools that do not implement VS3 ignore it;
standard XMRig clients pass it through without modification. No separate
identity system, account registration, or key distribution mechanism is needed
at the transport layer.

`routeVS3` is called from the `vs3-frame` event handler (line 742, the
main entrypoint). In this demo the handler decodes the frame payload as UTF-8
and logs it. In production it passes the frame to `StratumMessengerEngine` for
decryption.

### 3.5 Frame Embedding in Job Notifications (Download Path)

**Function:** `_makeJob()`, lines 637–687.
**Key lines:** 674–675.

```js
if (miner.pendingFrames?.length) {
  job.vs3 = miner.pendingFrames.shift().toString('hex');
}
```

The existing Stratum job notification object — which every pool sends to every
miner to assign new work — gains one optional field: `vs3`, containing the
hex-encoded frame bytes. One frame is delivered per job notification to bound
message size. Multiple queued frames are delivered in successive notifications.

Standard XMRig ignores unrecognized fields in job notifications. A VS3-aware
client reads the `vs3` field, decodes it from hex, and passes the raw frame to
the decryption pipeline. No new message type, no new TCP connection, no
additional port.

---

## 4. How to Run and Test

**Requirements:** Node.js >= 16. No npm packages required.

### Full bidirectional demo — Alice sends a message to Bob

This is the primary demo. It exercises the complete VS3 round-trip:
Alice encodes a message in ghost shares; the pool reassembles the frame
and delivers it to Bob via a job notification; Bob receives and displays it.
No Monero daemon required.

**Three terminals, three short commands:**

| Terminal | Command | Role |
|----------|---------|------|
| 1 | `node src/stratum-demo.js` | VS3-aware pool |
| 2 | `.\examples\bob.ps1` | Listener (recipient) |
| 3 | `.\examples\alice.ps1` | Sender |

Start Terminal 1 first, then 2, then 3.

**Expected pool output (Terminal 1):**
```
[VS3-Demo] Stratum listening on :4444
[VS3-Demo] Miner login: 4111111111111111...   ← Bob connects
[VS3-Demo] Miner login: 4222222222222222...   ← Alice connects
[VS3] Frame assembled from 422222222222... → 411111111111 (60B)
[VS3] Message: "Hello Bob! This message is hidden in mining traffic."
```

**Expected Bob output (Terminal 2):**
```
[VS3] Connected. Waiting for messages...
[VS3] ← Message received at HH:MM:SS:
      "Hello Bob! This message is hidden in mining traffic."
      (frame: 60B, version: 0x03, type: 0x01)
```

**Expected Alice output (Terminal 3):**
```
[VS3] Frame: 60B → 12 ghost shares
      Share  1/12 → nonce=aaaa0301
      Share  2/12 → nonce=aa000134
      ...
[VS3] All shares sent. Closing connection.
```

The nonce of every share begins with `aa` (the 0xAA sentinel). The payload
bytes for `"Hello Bob!..."` are visible in nonce[1..3] as UTF-8 hex — the
steganography is intentionally transparent in this plaintext POC.

### Bidirectional chat demo — Alice and Bob converse

This demo exercises the full round-trip in both directions simultaneously.
Both parties connect in `chat` mode and can type messages at any time.

| Terminal | Command | Role |
|----------|---------|------|
| 1 | `node src/stratum-demo.js` | VS3-aware pool |
| 2 | `.\examples\bob-chat.ps1` | Bob (chat, wallet 4111...) |
| 3 | `.\examples\alice-chat.ps1` | Alice (chat, wallet 4222...) |

**Expected experience:**

```
[VS3] Chat ready. Type a message and press Enter. (Ctrl+C to exit)

[you] Hello Alice!
[VS3] ← Message received at HH:MM:SS:
      "Hi Bob! This is a reply."
      (frame: 32B, version: 0x03, type: 0x01)

[you]
```

When a message arrives the `[you]` prompt is cleared, the message printed,
then the prompt restored — the interaction is fully inline.

### Alternative: single-client upload test

`test-ghost.js` tests the upload path only (no recipient listener required):

```
node test-ghost.js 127.0.0.1 4444
```

Sends the string `"Ciao dal test ghost share TNZX!"` (39B, 8 shares) to the
pool and confirms frame assembly. Useful for testing the pool in isolation.

### Observe the stats API

The pool exposes a lightweight HTTP monitoring endpoint on port 8090,
started automatically alongside the Stratum server. No extra command needed.

While the pool is running, open in a browser or run `curl`:

```
GET http://localhost:8090/stats
```

Returns:

```json
{"connected": 2, "ghostShares": 12, "vs3Frames": 1, "uptime": 18.2}
```

After the Alice→Bob demo: 2 connected miners (Alice + Bob), 12 ghost shares
assembled from a 60B frame (60 / 5 bytes per share = 12), 1 complete VS3 frame routed.

---

## 5. Threat Model and Limitations

**What this POC does not do:**

- **No encryption.** Frames are transmitted in plaintext. The production system
  uses X25519 key agreement + AES-256-GCM AEAD (HKDF-SHA256 key derivation) in
  `StratumMessengerEngine` (separate repository). This POC deliberately omits
  encryption so the steganographic transport is auditable without cryptographic
  tooling.

- **No TLS.** The demo runs plaintext TCP for readability. In production,
  Stratum connections use TLS, making the stream indistinguishable from HTTPS
  at the network layer. Adding TLS is one `tls.createServer()` call and is
  not architecturally significant.

- **No key distribution.** The `vs3_to` field carries a Monero wallet address
  as a routing identifier. How the sender obtains the recipient's public key
  for encryption is out of scope for this transport-layer POC.

- **No forward secrecy or authentication in this demo.** Those properties are
  provided by the `StratumMessengerEngine` layer, not by the transport.

- **No fragmentation across messages.** The current frame format supports
  fragmentation within a single message (`fragment_index` / `fragment_total`
  header fields), but `test-ghost.js` sends only single-fragment messages. The
  parser handles multi-fragment assembly correctly; the test client does not
  exercise it.

- **No resistance to an active adversary controlling the pool.** VS3 assumes
  the pool is trusted (or that frames are encrypted end-to-end before
  transmission). A malicious pool can read, drop, or delay frames. End-to-end
  encryption mitigates the read risk; the others are inherent in a relay
  architecture.

- **Throughput is low by design.** 5 bytes/share at practical ghost share
  rates yields ~300 bytes/minute. This is adequate for text messaging and key
  exchange, not for file transfer at scale. Higher throughput variants are
  possible but trade off against detectability and share acceptance rate.

- **The `0xAA` sentinel is a statistical anomaly in principle.** Any nonce
  byte has a 1/256 probability of being `0xAA`. At low difficulty, the pool
  additionally checks `miner.difficulty <= 500`, which eliminates false
  positives from high-difficulty real shares. However, a sufficiently motivated
  adversary who knows to look for the sentinel can distinguish ghost shares from
  real shares probabilistically, given a large enough traffic sample. A
  hardened version would use a keyed MAC or session-negotiated marker.

---

## 6. Relation to the Protocol Specification

This POC implements the VS3 steganographic transport layer as specified in the
public protocol repository:

**[https://github.com/tnzx-project/tnzx-protocol](https://github.com/tnzx-project/tnzx-protocol)**

The specification covers:

- VS3 frame format and field semantics (matches `GHOST_MAGIC`, `GHOST_HEADER` constants and the frame parser in `_handleGhostShare()` of `stratum-demo.js`)
- Ghost share encoding scheme — VS3-Monero profile: 5 bytes/share via nonce sentinel + ntime (matches `_handleGhostShare()` extraction logic)
- Indistinguishability properties and threat model
- Extension points for higher protocol layers (encryption, routing, identity)
- VS3-Generic profile (7 bytes/share, Bitcoin/Ethereum Stratum): test vectors published in `tnzx-protocol/test-vectors/vs3-vectors.json`, reference implementation pending

The protocol is published under MIT license. Any pool operator or client
developer can implement VS3 independently without dependency on TNZX
infrastructure. There is no proprietary relay service and no central authority.
Censoring one VS3-capable pool does not affect communication through other
pools.
