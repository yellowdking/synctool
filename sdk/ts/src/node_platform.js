// Node.js runtime capability detection and lazy built-in module loaders.
// Mapped to ./node_platform.browser.js under the "browser" condition so browser/PWA bundlers
// never see node:* specifiers in their module graph.

export function isNodeRuntime() {
  return typeof process !== 'undefined' && Boolean(process.versions?.node);
}

let nodeFsPromise = null;
export function loadNodeFs() {
  if (!nodeFsPromise) {
    nodeFsPromise = Promise.all([import('node:fs/promises'), import('node:path')]).then(([fs, path]) => ({
      fs,
      path,
    }));
  }
  return nodeFsPromise;
}

let nodeNetPromise = null;
export function loadNodeNet() {
  if (!nodeNetPromise) {
    nodeNetPromise = Promise.all([
      import('node:http'),
      import('node:tls'),
      import('node:crypto'),
      import('node:stream'),
    ]).then(([http, tls, crypto, stream]) => ({ http, tls, crypto, stream }));
  }
  return nodeNetPromise;
}
