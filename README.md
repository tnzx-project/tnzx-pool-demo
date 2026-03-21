# tnzx-vs3-demo

Proof-of-concept: two people exchange text messages over a cryptocurrency mining connection. To any observer on the network, only normal mining traffic is visible.

Built on the [TNZX VS3 protocol](https://github.com/tnzx-project/tnzx-protocol). No external dependencies. No Monero daemon required.

---

## What is happening

When a miner submits work to a pool, it sends small packets called "shares". Each share contains a `nonce` field — a number the miner is free to choose — and a `ntime` timestamp field.

VS3 hides message bytes inside those fields. The pool extracts them, reassembles the original message, and delivers it to the recipient by embedding it in a standard job notification. A recipient running VS3-aware software reads the message; any other standard mining client ignores the extra field silently.

The shares remain structurally valid Stratum protocol messages throughout.

**Scope of this demo:** This repository demonstrates the steganographic transport layer only — VS3 encoding, frame reassembly, and pool-side delivery. End-to-end encryption (X25519 ECDH + AES-256-GCM) and Mining Gate access control are implemented as separate modules in the [reference implementation](https://github.com/tnzx-project/tnzx-protocol/tree/main/reference-impl) and are not wired into this demo. Messages in this demo travel in plaintext inside the steganographic channel.

---

## Quick Start

**Requirements:** [Node.js](https://nodejs.org/) version 16 or later. That is all.

### Step 1 — Download

```
git clone https://github.com/tnzx-project/tnzx-pool-demo.git
cd tnzx-pool-demo
```

### Step 2 — Open three terminal windows

All three must be open at the same time. Start them in this order.

---

**Terminal 1 — start the pool**

```
node src/stratum-demo.js
```

You should see:
```
[VS3-Demo] TNZX VS3 Protocol Reference Implementation
[VS3-Demo] Stratum listening on :4444
[VS3-Demo] Stats API on :8090/stats
[VS3-Demo] Daemon: 127.0.0.1:38081
```

Leave this running.

---

**Terminal 2 — Bob connects (he will receive the message)**

On Windows:
```
.\examples\bob.ps1
```

On Linux/macOS:
```
node vs3-client.js listen 4111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111
```

You should see:
```
[VS3] Listener → 127.0.0.1:4444
[VS3] Connected. Waiting for messages...
```

Leave this running.

---

**Terminal 3 — Alice sends a message to Bob**

On Windows:
```
.\examples\alice.ps1
```

On Linux/macOS:
```
node vs3-client.js send 4222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222 4111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111 "Hello Bob! This message is hidden in mining traffic."
```

---

### What you should observe

**Terminal 1 (pool):**
```
[VS3-Demo] Miner login: 4111111111111111...
[VS3-Demo] Miner login: 4222222222222222...
[VS3] Frame assembled from 422222222222... → 411111111111... (60B)
[VS3] Message: "Hello Bob! This message is hidden in mining traffic."
```

**Terminal 2 (Bob):**
```
[VS3] ← Message received at HH:MM:SS:
      "Hello Bob! This message is hidden in mining traffic."
      (frame: 60B, version: 0x03, type: 0x01)
```

**Terminal 3 (Alice):**
```
[VS3] Frame: 60B → 12 ghost shares
      Share  1/12 → nonce=aaaa0301
      ...
[VS3] All shares sent. Closing connection.
```

Each nonce begins with `aa` (the 0xAA sentinel byte). The message bytes follow in plain hex — encryption is a separate layer not included in this demo.

---

## Bidirectional chat

Both parties can type and reply in real time.

**Terminal 1:** `node src/stratum-demo.js`

**Terminal 2 (Bob):**
```
.\examples\bob-chat.ps1
```

**Terminal 3 (Alice):**
```
.\examples\alice-chat.ps1
```

Type a message and press Enter. The other side receives it within a second.

---

## Test the upload path only

No recipient needed:

```
node test-ghost.js 127.0.0.1 4444
```

Expected pool output:
```
[VS3] Frame assembled from 4111111111... → broadcast (39B)
[VS3] Message: "Ciao dal test ghost share TNZX!"
```

---

## Stats API

While the pool is running:

```
GET http://localhost:8090/stats
```

Returns:
```json
{ "connected": 2, "ghostShares": 12, "vs3Frames": 1, "uptime": 18.2 }
```

`ghostShares` counts individual shares received; `vs3Frames` counts complete reassembled messages.

---

## Protocol specification

[tnzx-project/tnzx-protocol](https://github.com/tnzx-project/tnzx-protocol)

## License

MIT
