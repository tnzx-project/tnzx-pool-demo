'use strict';
/**
 * run-tests.js — Non-blocking test runner for the VS3 POC suite
 *
 * Executes each test file as a child process with a timeout. If one test hangs
 * or fails, the runner continues to the next. At the end it prints a summary
 * table with pass/fail per file and exits with code 0 (all pass) or 1 (any fail).
 *
 * Usage:  node poc/run-tests.js
 *         npm test
 *
 * @license LGPL-2.1
 */

const { execFile } = require('child_process');
const path = require('path');

const TIMEOUT_MS = 30000; // 30s per test — generous for slow CI machines

const TESTS = [
  'test-vs3-proxy.js',
  'test-hmac-sentinel.js',
  'test-dpi-steganalysis.js',
];

const pocDir = __dirname;

async function runOne(file) {
  const filePath = path.join(pocDir, file);
  const start = Date.now();

  return new Promise((resolve) => {
    const proc = execFile(process.execPath, [filePath], {
      timeout: TIMEOUT_MS,
      cwd: pocDir,
      env: { ...process.env },
      maxBuffer: 4 * 1024 * 1024,
    }, (err, stdout, stderr) => {
      const elapsed = Date.now() - start;
      const output = (stdout || '') + (stderr || '');

      if (err) {
        // Distinguish timeout from regular failure
        const timedOut = err.killed || err.signal === 'SIGTERM';
        resolve({
          file,
          pass: false,
          elapsed,
          timedOut,
          output,
          error: timedOut ? 'TIMEOUT' : (err.message || 'unknown error'),
        });
      } else {
        resolve({ file, pass: true, elapsed, timedOut: false, output, error: null });
      }
    });
  });
}

async function main() {
  console.log('');
  console.log('================================================================');
  console.log('  VS3 POC — Test Suite Runner');
  console.log('================================================================');
  console.log('');
  console.log(`Running ${TESTS.length} test files (timeout: ${TIMEOUT_MS / 1000}s each)`);
  console.log('');

  const results = [];

  for (const file of TESTS) {
    process.stdout.write(`  Running ${file} ... `);
    const result = await runOne(file);
    const status = result.pass ? 'PASS' : (result.timedOut ? 'TIMEOUT' : 'FAIL');
    console.log(`${status} (${(result.elapsed / 1000).toFixed(1)}s)`);

    // Show output for failed tests to aid debugging
    if (!result.pass) {
      const lines = result.output.trim().split('\n');
      // Show last 20 lines to keep output readable
      const tail = lines.slice(-20);
      for (const line of tail) {
        console.log(`    | ${line}`);
      }
      if (lines.length > 20) {
        console.log(`    | ... (${lines.length - 20} more lines above)`);
      }
      console.log('');
    }

    results.push(result);
  }

  // ── Summary ──
  const passCount = results.filter(r => r.pass).length;
  const failCount = results.length - passCount;

  console.log('');
  console.log('================================================================');
  console.log('  SUMMARY');
  console.log('================================================================');
  console.log('');
  for (const r of results) {
    const status = r.pass ? 'PASS' : (r.timedOut ? 'TIMEOUT' : 'FAIL');
    const pad = r.file.padEnd(30);
    console.log(`  [${status}]  ${pad}  ${(r.elapsed / 1000).toFixed(1)}s`);
  }
  console.log('');
  console.log(`  Total: ${passCount} passed, ${failCount} failed`);
  console.log('================================================================');
  console.log('');

  process.exit(failCount > 0 ? 1 : 0);
}

main();
