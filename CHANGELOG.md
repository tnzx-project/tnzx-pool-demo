# Changelog

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
