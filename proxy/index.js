/**
 * VS3 Proxy — Standalone Package Entry Point
 *
 * Exports the VS3Proxy class for programmatic use.
 * For CLI usage, see ./bin/vs3-proxy-cli.js
 *
 * Usage:
 *   const VS3Proxy = require('tnzx-vs3-proxy');
 *   const proxy = new VS3Proxy({ listenPort: 3333, upstream: 'pool.hashvault.pro:3333' });
 *   proxy.start();
 *
 * @license LGPL-2.1
 */

'use strict';

const VS3Proxy = require('../poc/vs3-proxy.js');

module.exports = VS3Proxy;
