# TNZX Pool Demo — Implementation Notes

This document describes the scope boundaries of the current proof-of-concept and planned extensions.

---

## Scope

This demo implements the **VS3-Monero profile** of the TNZX VS3 protocol: steganographic transport over Monero Stratum, 5 bytes per ghost share via nonce sentinel + ntime. It demonstrates the complete upload and download path in a self-contained Node.js server with no external dependencies.

## Planned Extensions (not in this release)

| ID | Description | Notes |
|----|-------------|-------|
| SPEC-01 | VS3-Generic profile (extranonce2-based encoding, 7 bytes/share) | Planned as milestone M2. Test vectors already published in `tnzx-protocol/test-vectors/vs3-vectors.json`. A client advertising the extranonce2 profile falls through to the standard share handler in this release. |
| SPEC-05 | Echo VERSION field in server ACK frames | No impact on current demo scenarios |
| QUA-03 | Structured logging (replace `console.log` with a log-level system) | Diagnostic output is readable for a demo; production pools would need log levels and sinks |
| COMPAT-03 | Graceful handling of server-initiated PING frames in `vs3-client.js` | Not triggered by current demo scenarios |
| EDGE-01 | Multi-fragment message concurrency from the same sender | `buildVS3Frame` uses `message_id=0x0001`; concurrent multi-fragment streams from one sender would collide in `fragmentBuffers`. The current demo sends single-fragment messages only. |
| EDGE-02 | Duplicate wallet login detection | `routeVS3` delivers to the first registered connection (Map insertion order); a second login with the same wallet silently fails. Not triggered in normal use. |

---

## Security Model

This is a proof-of-concept demo, not a production system. This codebase has **not undergone a formal security audit**; do not expose it to untrusted networks. See `DEMO_READING_GUIDE.md` for a detailed threat model.
