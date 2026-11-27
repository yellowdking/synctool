// Language-agnostic subprocess integration example using `synctool --json` (NDJSON over stdio).
// Suitable as a blueprint for Python, Rust, C#, AutoHotkey, Raycast, Swift, or shell wrappers.
//
// Security rules demonstrated:
// 1. NEVER pass `synctool://...#k=...` or `#s=...` in argv (`ps aux` visible); pass via env or `--stdin`.
// 2. Parse structured NDJSON lines from `stdout` (`type = "event" | "result" | "error"`).
// 3. Branch on frozen `error.code` / exit code `0..6`, never on localized human text.
//
// Run offline self-check:
//   node ./examples/cli-subprocess/sync_helper.mjs --self-test

import { spawn } from 'node:child_process';
import assert from 'node:assert/strict';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

/**
 * Parse NDJSON stdout emitted by `synctool --json <subcommand>`.
 * @param {string} rawStdout
 */
export function parseSynctoolNDJSON(rawStdout) {
  const events = [];
  let result = null;
  let syncError = null;

  for (const rawLine of rawStdout.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line) continue;
    const msg = JSON.parse(line);
    if (msg.type === 'event') events.push(msg);
    else if (msg.type === 'result') result = msg.data;
    else if (msg.type === 'error') syncError = msg.error;
  }
  return { events, result, syncError };
}

/**
 * Invoke `synctool --json` safely with secrets passed via environment / stdin.
 * @param {string} binPath
 * @param {string[]} args
 * @param {{ env?: Record<string, string>, stdinText?: string }} [opts]
 */
export function invokeSynctoolJSON(binPath, args, opts = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(binPath, ['--json', ...args], {
      env: { ...process.env, ...opts.env },
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.on('error', reject);
    child.on('close', (exitCode) => {
      const parsed = parseSynctoolNDJSON(stdout);
      resolve({ exitCode: exitCode ?? 1, ...parsed, stderr });
    });
    if (opts.stdinText !== undefined) child.stdin.write(opts.stdinText);
    child.stdin.end();
  });
}

// Offline contract verification (`node ./examples/cli-subprocess/sync_helper.mjs --self-test`)
const isMain = Boolean(process.argv[1]) && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url;
if (isMain && (process.argv.includes('--self-test') || process.argv.length <= 2)) {
  const sampleNDJSON = [
    JSON.stringify({ type: 'event', event: 'transfer_progress', stage: 'transferring', bytes_done: 4112, bytes_total: 4112 }),
    JSON.stringify({ type: 'result', data: { mode: 'spool', msg_id: '0123456789abcdef0123456789abcdef', total_bytes: 4112 } }),
  ].join('\n');
  const parsed = parseSynctoolNDJSON(sampleNDJSON);
  assert.equal(parsed.events.length, 1);
  assert.equal(parsed.result.mode, 'spool');
  assert.equal(parsed.syncError, null);
  console.log('ok: synctool --json NDJSON subprocess parser verified');
}
