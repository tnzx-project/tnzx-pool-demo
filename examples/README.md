# Examples

Two demo scenarios: one-way message delivery and bidirectional chat.

All commands are run from the **project root** (`tnzx-pool-demo/`), not from this directory.

---

## Prerequisites

Node.js 16 or later. No other dependencies.

```
git clone https://github.com/tnzx-project/tnzx-pool-demo.git
cd tnzx-pool-demo
```

---

## Scenario 1 — Alice sends a message to Bob

Open **three terminal windows**, all in the project root.

**Terminal 1 — start the pool**
```
node src/stratum-demo.js
```
Expected:
```
[VS3-Demo] Stratum listening on :4444
[VS3-Demo] Stats API on :8090/stats
```
Leave running.

**Terminal 2 — Bob listens**

Windows:
```
.\examples\bob.ps1
```
Linux / macOS:
```
node vs3-client.js listen 4111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111
```
Expected:
```
[VS3] Listener → 127.0.0.1:4444
[VS3] Connected. Waiting for messages...
```
Leave running.

**Terminal 3 — Alice sends**

Windows:
```
.\examples\alice.ps1
```
Linux / macOS:
```
node vs3-client.js send \
  4222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222 \
  4111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111 \
  "Hello Bob! This message is hidden in mining traffic."
```

**What you should see**

Terminal 1 (pool):
```
[VS3-Demo] Miner login: 4111111111111111...
[VS3-Demo] Miner login: 4222222222222222...
[VS3] Frame assembled from 422222... → 411111... (60B)
[VS3] Message: "Hello Bob! This message is hidden in mining traffic."
```

Terminal 2 (Bob):
```
[VS3] ← Message received:
      "Hello Bob! This message is hidden in mining traffic."
      (frame: 60B, version: 0x03, type: 0x01)
```

Terminal 3 (Alice):
```
[VS3] Frame: 60B → 12 ghost shares
      Share  1/12 → nonce=aaaa0301
      ...
[VS3] All shares sent.
```

Each nonce starts with `aa` (the 0xAA VS3 sentinel byte). The message payload follows in the subsequent bytes. Encryption is a separate layer not included in this demo — see [tnzx-protocol](https://github.com/tnzx-project/tnzx-protocol) for the full reference implementation.

---

## Scenario 2 — Bidirectional chat

Open three terminals in the project root.

**Terminal 1 — pool**
```
node src/stratum-demo.js
```

**Terminal 2 — Bob**

Windows:
```
.\examples\bob-chat.ps1
```
Linux / macOS:
```
node vs3-client.js chat \
  4111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111 \
  4222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222
```

**Terminal 3 — Alice**

Windows:
```
.\examples\alice-chat.ps1
```
Linux / macOS:
```
node vs3-client.js chat \
  4222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222 \
  4111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111
```

Type a message in either terminal and press Enter. The other side receives it within a second or two depending on share submission rate.

---

## Quick upload test (no recipient needed)

```
node test-ghost.js 127.0.0.1 4444
```

The pool will log the assembled frame. Useful for testing the encoding path in isolation.

---

## Address format

The long hex strings (`4111...`, `4222...`) are demo wallet addresses. In this demo they serve as sender and recipient identifiers. In a real VS3 deployment these would be the actual Monero wallet addresses used by the mining clients.

---

## What is not included in this demo

| Feature | Where to find it |
|---------|-----------------|
| End-to-end encryption (X25519 + XChaCha20-Poly1305) | [tnzx-protocol/reference-impl](https://github.com/tnzx-project/tnzx-protocol) |
| Mining Gate (hashrate-gated access control) | [tnzx-protocol/reference-impl](https://github.com/tnzx-project/tnzx-protocol) |
| VS3-Generic profile (Bitcoin/Ethereum Stratum) | Planned — milestone M2 |
| Anonymous group coordination (Falo) | [tnzx-protocol/papers/falo](https://github.com/tnzx-project/tnzx-protocol/tree/main/papers/falo) |
