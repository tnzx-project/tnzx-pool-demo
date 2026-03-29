# VS3 Proof of Concept

Working demonstrations of the Visual Stratum protocol on real mining infrastructure.

## What This Proves

1. **V1 steganography** — 1 byte per share hidden in the nonce LSB of real, validated mining shares. The pool processes the share, pays the miner, and never knows a message was present. Works on any PoW chain.

2. **V2 steganography** — 3 bytes per share using nonce LSB + extranonce2 trailing bytes. Standard Bitcoin Stratum fields. No protocol extensions.

3. **VS3 proxy** — A TCP proxy between miners and any standard pool. Extracts V1/V2 from real shares, intercepts V3 ghost shares, routes messages between connected miners. The pool is unmodified.

4. **Mining Gate** — Proof-of-work access control. Miners must submit 3 real shares before the proxy accepts ghost shares. Anti-Sybil without registration.

5. **Alice-to-Bob messaging** — Two miners connect to the same proxy, mine on a real pool, and exchange messages. The pool sees two normal miners. Nothing else.

## Test Results (2026-03-29)

All tests run against production mining pools.

| Test | Pool | Chain | Encoding | Shares | Message | Result |
|------|------|-------|----------|--------|---------|--------|
| V1 stego | HashVault | Monero | 1 B/share (nonce LSB) | 30 | "I am safe. I love you." | **EXACT** |
| V2 stego | Braiins Pool | Bitcoin | 3 B/share (nonce + en2) | 10 | "I am safe. I love you." | **EXACT** |
| Alice→Bob | HashVault | Monero | V3 ghost (5 B/share) | 9 | "I am safe. Meet me at the bridge." | **EXACT** |

Full transcripts with timestamps in `results/`.

## Files

### Core

- **vs3-proxy.js** — The VS3 middleware proxy. Full protocol stack: Mining Gate, V1/V2/V3 extraction, ghost share interception, message routing, WebSocket relay. ~700 lines, zero dependencies.

### Proof Transcripts (run against real pools)

- **run-v1-proof.js** — V1 steganography on HashVault (Monero). Message hidden in nonce LSB of real mining shares.
- **run-v2-proof.js** — V2 steganography on Braiins Pool (Bitcoin). 3 bytes/share in nonce + extranonce2.
- **run-alice-bob-proof.js** — Bidirectional messaging through HashVault. Alice sends, Bob receives. Pool sees nothing.

### Additional Tests

- **test-vs3-proxy.js** — Unit test with mock pool. Verifies Mining Gate blocking, ghost share interception, frame assembly.
- **test-full-stack.js** — All protocol layers on a real Monero pool: Mining Gate + V3 + V1 + WebSocket.
- **test-bitcoin-pool.js** — V1 + V2 + Mining Gate on a real Bitcoin pool.
- **test-real-pool.js** — Proxy connectivity and ghost share handling on real Monero pools.
- **test-alice-bob.js** — Bidirectional messaging test.

### Results

- **results/01-v1-monero-hashvault.txt** — V1 proof transcript with timestamps
- **results/02-v2-bitcoin-braiins.txt** — V2 proof transcript with timestamps
- **results/03-alice-bob-hashvault.txt** — Alice-Bob proof transcript with timestamps

## How It Works

```
[Miner A] ──Stratum──▶ [VS3 Proxy] ──Stratum──▶ [Any Standard Pool]
[Miner B] ──Stratum──▶ [VS3 Proxy]               (pays both miners)
                            │
                      Extracts V1/V2 from real shares
                      Intercepts V3 ghost shares
                      Routes messages between A and B
                      Pool sees normal mining traffic
```

### V1: Truly Steganographic (1 byte/share)

The miner constrains the two least-significant nibbles of the nonce to carry one payload byte, then searches for a valid PoW solution in the remaining bits. The share is real. The pool validates it. An observer cannot distinguish it from an ordinary share.

### V2: Triple Bandwidth (3 bytes/share)

Extends V1 with 2 bytes from extranonce2 trailing bytes. Bitcoin Stratum standard fields — no protocol extension needed.

### V3: High Bandwidth (5 bytes/share)

Ghost shares with sentinel nonce (0xAA) and zero result. The proxy intercepts them before they reach the pool. Higher bandwidth but detectable. Optional.

### Mining Gate

State machine: INACTIVE → GRACE → ACTIVE ↔ SUSPENDED. Opens after 3 real validated shares. Gates access to V3 ghost shares and messaging. Provides Sybil resistance through proof-of-work.

## Running

```bash
# V1 proof on real Monero pool
node poc/run-v1-proof.js

# V2 proof on real Bitcoin pool
node poc/run-v2-proof.js

# Alice-Bob messaging on real pool
node poc/run-alice-bob-proof.js

# Unit test with mock pool (no internet needed)
node poc/test-vs3-proxy.js
```

## License

LGPL-2.1
