// Browser-safe platform stub (zero node:* imports for Webpack / Vite / Rollup / esbuild / Metro).

import { ErrorCode, SyncError } from './errors.js';

export function isNodeRuntime() {
  return false;
}

export function loadNodeFs() {
  return Promise.reject(
    new SyncError(
      ErrorCode.ERR_STORAGE_IO,
      'Node.js filesystem helpers are unavailable in browser runtimes; use IndexedDB / Web Blob APIs',
    ),
  );
}

export function loadNodeNet() {
  return Promise.reject(
    new SyncError(
      ErrorCode.ERR_TLS_CERT_INVALID,
      'browser sandbox cannot perform custom Node TLS SPKI pinning; use HTTPS domain with system_ca',
    ),
  );
}
