# Examples

End-to-end encrypted chat hidden in mining traffic.

All commands are run from the **project root** (`tnzx-pool-demo/`), not from this directory.

---

## Prerequisites

Node.js 16 or later. No other dependencies.

```
git clone https://github.com/tnzx-project/tnzx-pool-demo.git
cd tnzx-pool-demo
```

---

## Encrypted Chat — Alice and Bob

Open **three terminal windows**, all in the project root.

**Terminal 1 — start the pool**
```
node src/stratum-demo.js
```

**Terminal 2 — Bob**
```
node vs3-chat.js 4111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111 4222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222
```

**Terminal 3 — Alice**
```
node vs3-chat.js 4222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222 4111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111
```

Wait for both sides to show `E2E encryption active`, then type a message in either terminal.

**What you should see**

Terminal 3 (Alice types "Hello Bob"):
```
  [send] 9B text + 104B crypto overhead = 113B → 25 ghost shares
```

Terminal 2 (Bob receives):
```
  16:55:36 [peer] Hello Bob
```

Terminal 1 (pool log):
```
  [VS3] Frame assembled from 422222... → 411111... (122B)
  [VS3] Message: "9Tq█▓░...░▓█" | type=0x05
```

The pool sees only opaque ciphertext (type 0x05 = ENCRYPTED). It cannot read the message content.

---

## What happens under the hood

1. Each client generates a fresh **X25519 keypair** at startup
2. Clients exchange public keys via **KEY_EXCHANGE** ghost shares (type 0x04)
3. Each message is encrypted with **XChaCha20-Poly1305** using a fresh ephemeral key (PFS)
4. The encrypted payload is split into **5-byte ghost shares** hidden in Stratum nonce/ntime fields
5. The pool assembles the frame and routes it to the recipient via a job notification
6. The recipient decrypts using their persistent private key

Every message uses a new ephemeral keypair. Compromising one message does not compromise past or future messages (Perfect Forward Secrecy).

---

## Quick upload test (no encryption, no recipient)

```
node test-ghost.js 127.0.0.1 4444
```

The pool will log the assembled frame. Useful for testing the encoding path in isolation.

---

## Plaintext chat (legacy, no encryption)

For testing the transport layer without encryption:

```
node vs3-client.js chat <myWallet> <peerWallet>
```

---

## Address format

The long hex strings (`4111...`, `4222...`) are demo wallet addresses. In a real VS3 deployment these would be actual Monero wallet addresses used by the mining clients.
