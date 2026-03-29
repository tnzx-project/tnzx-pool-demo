# TNZX VS3 — Pool Demo and Proxy POC

Proof-of-concept implementations of the [Visual Stratum protocol](https://github.com/tnzx-project/tnzx-protocol). Two deployment models demonstrated:

1. **VS3 Proxy** (`poc/`) — sits between any miner and any standard pool. Extracts steganographic data from real shares, intercepts ghost shares, routes messages. The pool is unmodified.
2. **VS3-Aware Pool** (`src/stratum-demo.js`) — a Stratum server with native ghost share detection and message routing.

Both share the same frame format and encoding. No external dependencies. Node.js 16+.

---

## Test Results (2026-03-29)

All tests run against production mining pools.

| Test | Pool | Chain | Encoding | Message | Result |
|------|------|-------|----------|---------|--------|
| V1 stego | HashVault | Monero | 1 B/share (nonce LSB) | "I am safe. I love you." | **EXACT** |
| V2 stego | Braiins Pool | Bitcoin | 3 B/share (nonce + extranonce2) | "I am safe. I love you." | **EXACT** |
| Alice-Bob | HashVault | Monero | V3 ghost (5 B/share) | "I am safe. Meet me at the bridge." | **EXACT** |

Timestamped transcripts: [`poc/results/`](poc/results/)

---

## Quick Start — Proxy (any pool)

```bash
# V1 steganography proof on real Monero pool
node poc/run-v1-proof.js

# V2 steganography proof on real Bitcoin pool
node poc/run-v2-proof.js

# Alice-to-Bob messaging on real pool
node poc/run-alice-bob-proof.js
```

See [`poc/README.md`](poc/README.md) for full documentation.

## Quick Start — Pool Demo (self-contained)

```bash
# Terminal 1: start pool
node src/stratum-demo.js

# Terminal 2: Bob listens
node vs3-client.js listen <bob_wallet>

# Terminal 3: Alice sends
node vs3-client.js send <alice_wallet> <bob_wallet> "Hello Bob!"
```

See [`TECHNICAL_GUIDE.md`](TECHNICAL_GUIDE.md) for code walkthrough.

---

## Architecture

```
Model 1 — Proxy (no pool modification):

  [Alice] --Stratum--> [VS3 Proxy] --Stratum--> [Any Standard Pool]
  [Bob]   --Stratum--> [VS3 Proxy]               (pays both miners)
                            |
                      V1/V2 extraction from real shares
                      V3 ghost share interception
                      Message routing between miners

Model 2 — VS3-Aware Pool (native support):

  [Alice] --Stratum--> [VS3 Pool] --routes--> [Bob]
                            |
                      Ghost share detection
                      Frame assembly
                      Job notification injection
```

## Encoding Profiles

| Profile | Bytes/share | How | Stealth | Chain |
|---------|-------------|-----|---------|-------|
| **V1** | 1 | Nonce LSB nibbles (real share) | Maximum | Any |
| **V2** | 3 | V1 + extranonce2 (real share) | Maximum | Bitcoin |
| **V3** | 5 | Ghost share (sentinel 0xAA) | Lower | Monero |

V1 and V2 are truly steganographic — the shares pass full PoW validation. V3 is an optional bandwidth boost with a detectable sentinel.

---

## Repository Structure

```
src/stratum-demo.js     VS3-aware Stratum pool (~730 lines)
vs3-client.js           VS3 ghost share client
test-ghost.js           Upload path test
poc/
  vs3-proxy.js          VS3 middleware proxy (~700 lines)
  run-v1-proof.js       V1 proof on real Monero pool
  run-v2-proof.js       V2 proof on real Bitcoin pool
  run-alice-bob-proof.js  Bidirectional messaging proof
  results/              Timestamped transcripts
  README.md             Proxy documentation
TECHNICAL_GUIDE.md      Pool demo code walkthrough
```

## Protocol Specification

[tnzx-project/tnzx-protocol](https://github.com/tnzx-project/tnzx-protocol)

## License

LGPL-2.1
