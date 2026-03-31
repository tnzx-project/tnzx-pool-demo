#!/usr/bin/env node

/**
 * VS3 Proxy — Standalone CLI
 *
 * Deploy between ANY miner and ANY pool.
 * Zero pool modification required. Pool sees only normal mining traffic.
 *
 * Usage:
 *   vs3-proxy --upstream pool.hashvault.pro:3333 --listen 13333
 *   vs3-proxy --upstream stratum+tcp://braiins.com:3333 --listen 13333 --ws 19090
 *   vs3-proxy --config ./proxy.json
 *
 * Then point your miner to localhost:13333 instead of the pool directly.
 *
 * What happens:
 *   [Your Miner] ──Stratum──▶ [VS3 Proxy :13333] ──Stratum──▶ [Any Pool]
 *                                     │
 *                              Mining Gate (anti-Sybil)
 *                              V1 extraction (1 byte/share)
 *                              Ghost share parsing (V3)
 *                              WebSocket relay (:19090)
 *
 * The pool sees normal mining traffic. Nothing else.
 *
 * @license LGPL-2.1
 */

'use strict';

const VS3Proxy = require('../index.js');
const fs = require('fs');
const path = require('path');

// ── Parse arguments ──

function parseArgs(argv) {
  const args = {
    upstream: null,
    listen: 13333,
    ws: 19090,
    config: null,
    verbose: false,
    hmac: false
  };

  for (let i = 2; i < argv.length; i++) {
    switch (argv[i]) {
      case '--upstream': case '-u': args.upstream = argv[++i]; break;
      case '--listen': case '-l': args.listen = parseInt(argv[++i]); break;
      case '--ws': case '-w': args.ws = parseInt(argv[++i]); break;
      case '--config': case '-c': args.config = argv[++i]; break;
      case '--verbose': case '-v': args.verbose = true; break;
      case '--hmac': args.hmac = true; break;
      case '--help': case '-h': printUsage(); process.exit(0);
      default:
        if (!args.upstream && !argv[i].startsWith('-')) {
          args.upstream = argv[i];
        }
    }
  }

  // Load config file if specified
  if (args.config) {
    try {
      const configPath = path.resolve(args.config);
      const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
      Object.assign(args, config);
    } catch (e) {
      console.error(`Failed to load config: ${e.message}`);
      process.exit(1);
    }
  }

  return args;
}

function printUsage() {
  console.log(`
VS3 Proxy — Universal Stratum Steganographic Relay

USAGE:
  vs3-proxy --upstream <pool:port> [options]
  vs3-proxy <pool:port> [options]

OPTIONS:
  --upstream, -u <host:port>   Upstream pool address (required)
  --listen, -l <port>          Local Stratum listen port (default: 13333)
  --ws, -w <port>              WebSocket relay port (default: 19090)
  --config, -c <file>          Load config from JSON file
  --verbose, -v                Verbose logging
  --hmac                       Enable HMAC sentinel mode (Appendix D)
  --help, -h                   Show this help

EXAMPLES:
  # Monero via HashVault
  vs3-proxy --upstream pool.hashvault.pro:3333

  # Bitcoin via Braiins
  vs3-proxy --upstream stratum.braiins.com:3333 --listen 3333

  # With config file
  vs3-proxy --config ./my-proxy.json

CONFIG FILE FORMAT:
  {
    "upstream": "pool.hashvault.pro:3333",
    "listen": 13333,
    "ws": 19090,
    "hmac": false
  }

THEN:
  Point your miner to localhost:<listen-port> instead of the pool.
  The pool sees normal mining traffic. VS3 messages are invisible.
`);
}

// ── Parse upstream address ──

function parseUpstream(addr) {
  if (!addr) return null;
  // Strip protocol prefix
  const clean = addr.replace(/^stratum\+tcp:\/\//, '').replace(/^tcp:\/\//, '');
  const parts = clean.split(':');
  if (parts.length !== 2 || !parts[1]) return null;
  return { host: parts[0], port: parseInt(parts[1]) };
}

// ── Main ──

const args = parseArgs(process.argv);

if (!args.upstream) {
  console.error('Error: --upstream <pool:port> required');
  console.error('Run with --help for usage');
  process.exit(1);
}

const upstream = parseUpstream(args.upstream);
if (!upstream || isNaN(upstream.port)) {
  console.error(`Error: invalid upstream address: ${args.upstream}`);
  console.error('Expected format: host:port (e.g., pool.hashvault.pro:3333)');
  process.exit(1);
}

console.log(`
╔══════════════════════════════════════════════╗
║         VS3 Proxy — Standalone Relay         ║
╠══════════════════════════════════════════════╣
║  Upstream:  ${(upstream.host + ':' + upstream.port).padEnd(32)}║
║  Listen:    :${String(args.listen).padEnd(31)}║
║  WebSocket: :${String(args.ws).padEnd(31)}║
║  HMAC:      ${String(args.hmac).padEnd(32)}║
╚══════════════════════════════════════════════╝
`);

const proxy = new VS3Proxy({
  listenPort: args.listen,
  upstreamHost: upstream.host,
  upstreamPort: upstream.port,
  wsPort: args.ws,
  hmacEnabled: args.hmac
});

// ── Event logging ──

proxy.on('connection', ({ id, wallet }) => {
  console.log(`[+] Miner connected: ${id}${wallet ? ` (${wallet.slice(0, 12)}...)` : ''}`);
});

proxy.on('disconnection', ({ id }) => {
  console.log(`[-] Miner disconnected: ${id}`);
});

proxy.on('gate-opened', ({ wallet }) => {
  if (args.verbose) console.log(`[GATE] Opened for ${wallet.slice(0, 12)}...`);
});

proxy.on('vs3-frame', ({ from, to, channel, size }) => {
  if (args.verbose) {
    console.log(`[VS3] ${channel.toUpperCase()} frame: ${from?.slice(0, 8) || '?'}→${to?.slice(0, 8) || '?'} (${size}B)`);
  }
});

proxy.on('ws-message', ({ from, to }) => {
  if (args.verbose) {
    console.log(`[WS] ${from.slice(0, 8)}→${to.slice(0, 8)}`);
  }
});

// ── Stats (every 60s if verbose) ──

if (args.verbose) {
  setInterval(() => {
    const s = proxy.stats;
    console.log(`[STATS] Miners: ${proxy.connections.size} | V1: ${s.v1Bytes || 0}B | Ghost: ${s.ghostShares || 0} | WS: ${s.wsMessages || 0}`);
  }, 60000);
}

// ── Start ──

proxy.start();

console.log(`Proxy listening. Point your miner to localhost:${args.listen}`);
console.log('Press Ctrl+C to stop.\n');

// ── Graceful shutdown ──

process.on('SIGINT', () => {
  console.log('\nShutting down...');
  proxy.stop();
  process.exit(0);
});

process.on('SIGTERM', () => {
  proxy.stop();
  process.exit(0);
});
