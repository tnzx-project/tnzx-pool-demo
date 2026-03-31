# Changelog

## [1.4.1] — 2026-03-31

### Fixed
- **BUG-04 (CRITICAL):** Multi-fragment messages now route to the correct recipient
  instead of broadcasting. `stratum-demo.js` used a local variable (`shareGhostTo`)
  that was null on non-first shares; replaced with persistent `miner.ghostTo`.
  `vs3-proxy.js` added `_lastGhostTo` fallback for edge case where single-fragment
  delivery clears `ghostTo` before multi-fragment entry is created.
- **SEC:** `_lastGhostTo` now cleared after every delivery to prevent stale routing
  state from misdirecting subsequent messages to previous recipients.
- **SEC:** `_lastGhostTo` fallback restricted to ghost channel only — V1/V2 channels
  no longer inherit ghost share routing targets.
- **BUG-07:** Job Map FIFO eviction cap reduced from 100 to 50 entries to limit
  memory growth on long-running deployments.
- Stale comment at `stratum-demo.js:543` corrected (referenced `shareGhostTo`
  but code uses `miner.ghostTo`).

### Added
- `poc/test-hmac-sentinel.js` — 18 unit tests validating HMAC rotating sentinel
  (Appendix D): key derivation, verification, DPI resistance (78+ unique sentinel
  values per 100 samples), cross-miner isolation.
- `v2BytesExtracted` counter initialized in proxy stats.
- HMAC helper functions exported for unit testing (`module.exports._hmac`).

### Verified
- Security audit: no confidentiality violations after fixes
- Code review: all fix paths traced for single-fragment, multi-fragment,
  sequential messages, and interleaved fragments
- Reference implementation: 37/37 tests pass
- Proxy mock test: all checks pass, zero ghost share leakage
- HMAC sentinel: 18/18 tests pass

## [1.4.0] — 2026-03-30

### Added
- Bidirectional Alice-Bob messaging test via VS3 proxy on standard pool (HashVault)
- Test transcript: `poc/results/04-alice-bob-bidirectional-hashvault.txt`
- HMAC rotating sentinel support in VS3 proxy (Appendix D of Visual Stratum paper)
- HMAC bidirectional test: `poc/results/05-alice-bob-hmac-hashvault.txt`

### Verified
- VS3 proxy routes messages between two miners through a standard, unmodified Monero pool
- Zero ghost shares leaked to upstream pool
- Mining Gate activation with 3 real shares per miner
- HMAC sentinel eliminates fixed 0xAA pattern — 16/16 sentinel bytes unique, none equal 0xAA
- DPI-level detection of ghost shares eliminated (only PoW verification can distinguish them)

## [1.3.0] — 2026-03-28

### Added
- `poc/vs3-proxy.js` — VS3 middleware proxy (full stack: Mining Gate, V1/V2/V3 channels, WebSocket relay)
- `poc/test-vs3-proxy.js` — mock pool proxy test
- `poc/test-real-pool.js` — real Monero pool connectivity test
- `poc/test-alice-bob.js` — bidirectional messaging through real pool (HashVault)
- `poc/test-full-stack.js` — full protocol stack test (Mining Gate + V1 + V3 + WebSocket) on real pool
- `poc/test-bitcoin-pool.js` — VS3 on Bitcoin (Braiins Pool), proving chain-agnostic design

### Changed
- License from MIT to LGPL-2.1

### Fixed
- VS3 frame version byte in header comment (0x01 → 0x03)

## [1.2.0] — 2026-03-23

### Added
- Bidirectional chat mode (`chat` command in `vs3-client.js`)
- Stats API on port 8090 (`GET /stats` endpoint)
- `GRANT_REVIEWERS_GUIDE.md` for technical grant reviewers
- `CODE-REVIEW.md` documenting pre-publication review findings

### Fixed
- Ghost share detection: difficulty threshold now configurable via `ghostDiffMax`
- Frame reassembly buffer overflow guard (4 KB cap per connection)
- VS3 frame routing: recipient identified by wallet address in `vs3_to` field

## [1.1.0] — 2026-03-21

### Added
- PowerShell example scripts for Windows (`examples/`)
- Docker support (`Dockerfile`, `docker-compose.yml`)
- `test-ghost.js` for isolated upload-path testing

### Changed
- `vs3-client.js`: added `listen` mode for persistent recipient connections
- README: full Quick Start with three-terminal walkthrough

## [1.0.0] — 2026-03-15 — Initial release

First public release of the TNZX VS3 pool demo.

Demonstrates the complete VS3 protocol round-trip over standard Stratum:
ghost share upload (miner → pool) and VS3 frame delivery via job notification
(pool → recipient miner). Includes send mode, listen mode, and bidirectional
chat mode.

See [TECHNICAL_GUIDE.md](TECHNICAL_GUIDE.md) for implementation details.
