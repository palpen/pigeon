import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import net from 'node:net';
import {fileURLToPath} from 'node:url';
import {createApp} from './server.js';
import {privateDirectory} from './security.js';

async function removeStaleSocket(socketPath) {
  let before;
  try { before = fs.lstatSync(socketPath); }
  catch (err) { if (err.code === 'ENOENT') return; throw err; }
  if (!before.isSocket()) throw new Error('Socket path contains a non-socket file.');
  await new Promise((resolve, reject) => {
    const probe = net.connect(socketPath);
    probe.setTimeout(1000, () => { probe.destroy(); reject(new Error('Socket probe timed out; refusing to replace it.')); });
    probe.once('connect', () => { probe.destroy(); reject(new Error('Pigeon socket is already in use.')); });
    probe.once('error', err => {
      if (err.code !== 'ECONNREFUSED') return reject(new Error('Socket probe failed; refusing to replace it.'));
      try {
        const after = fs.lstatSync(socketPath);
        if (before.dev !== after.dev || before.ino !== after.ino) throw new Error('Socket changed during startup.');
        fs.unlinkSync(socketPath);
        resolve();
      } catch (error) { reject(error); }
    });
  });
}

const listen = (server, ...args) => new Promise((resolve,reject) => {
  server.once('error',reject);
  server.listen(...args,() => {server.removeListener('error',reject);resolve();});
});
const closeServer = server => new Promise(resolve => server.close(resolve));

export async function start({dataDir = process.env.DATA_DIR || path.join(path.dirname(fileURLToPath(import.meta.url)), 'data'),
  port = process.env.PORT ?? 8787, handleSignals = true, ...options} = {}) {
  if (!/^\d+$/.test(String(port)) || Number(port) > 65535) throw new Error('PORT must be an integer from 0 to 65535.');
  port = Number(port);
  dataDir = path.resolve(dataDir);
  // Acquire the OS-backed data lock before probing or unlinking the socket.
  const instance = createApp({dataDir, ...options});
  const proxy = http.createServer(instance.proxyHandler);
  const local = http.createServer(instance.app);
  proxy.requestTimeout = local.requestTimeout = 120_000;
  const socketPath = path.join(dataDir,'run','pigeon.sock');
  try {
    fs.mkdirSync(path.dirname(socketPath), {recursive:true,mode:0o700});
    privateDirectory(path.dirname(socketPath));
    // macOS sockaddr_un.sun_path has room for 103 bytes plus its terminator.
    if (Buffer.byteLength(socketPath) > 103) throw new Error('DATA_DIR is too long for a portable Unix socket path.');
    await removeStaleSocket(socketPath);
    await listen(proxy,socketPath);
    fs.chmodSync(socketPath,0o600);
    await listen(local,port,'127.0.0.1');
  } catch (err) {
    await Promise.all([closeServer(proxy), closeServer(local)]);
    await instance.close();
    throw err;
  }
  let stopping;
  const stop = () => {
    if (stopping) return stopping;
    process.removeListener('SIGTERM',onSignal);
    process.removeListener('SIGINT',onSignal);
    stopping = (async () => {
      const timer = setTimeout(() => {proxy.closeAllConnections();local.closeAllConnections();},5000);
      timer.unref();
      await Promise.all([closeServer(proxy),closeServer(local)]);
      clearTimeout(timer);
      await instance.close();
    })();
    return stopping;
  };
  const onSignal = () => { void stop(); };
  if (handleSignals) {
    process.once('SIGTERM',onSignal);
    process.once('SIGINT',onSignal);
  }
  return {proxy,local,stop,socketPath};
}
