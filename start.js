import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import net from 'node:net';
import {fileURLToPath} from 'node:url';
import {createApp} from './server.js';

export async function start() {
  const root = path.dirname(fileURLToPath(import.meta.url));
  const dataDir = path.resolve(process.env.DATA_DIR || path.join(root,'data'));
  const runDir = path.join(dataDir,'run');
  fs.mkdirSync(runDir,{recursive:true,mode:0o700});
  const stat = fs.lstatSync(runDir);
  if (!stat.isDirectory() || stat.uid !== process.getuid()) throw new Error('Socket directory must be owned by the service user.');
  fs.chmodSync(runDir,0o700);
  const socketPath = path.join(runDir,'pigeon.sock');
  if (fs.existsSync(socketPath)) {
    if (!fs.lstatSync(socketPath).isSocket()) throw new Error('Socket path contains a non-socket file.');
    await new Promise((resolve,reject) => {
      const probe = net.connect(socketPath);
      probe.once('connect',() => {probe.destroy(); reject(new Error('Pigeon is already running for this data directory.'));});
      probe.once('error',err => {
        if (err.code !== 'ECONNREFUSED' && err.code !== 'ENOENT') return reject(err);
        // A crashed server can leave its socket behind. Never remove a live one.
        if (err.code === 'ECONNREFUSED') fs.unlinkSync(socketPath);
        resolve();
      });
    });
  }
  const proxy = http.createServer();
  const local = http.createServer();
  let instance;
  const listen = (server,...args) => new Promise((resolve,reject) => {
    server.once('error',reject);
    server.listen(...args,() => {server.removeListener('error',reject);resolve();});
  });
  try {
    await listen(proxy,socketPath);
    fs.chmodSync(socketPath,0o600);
    instance = createApp({dataDir});
    proxy.on('request',instance.app);
    local.on('request',instance.app);
    await listen(local,8787,'127.0.0.1');
  } catch (err) {
    proxy.close(); local.close(); instance?.close(); throw err;
  }
  console.log(`Pigeon: local token API on 127.0.0.1:8787; Tailscale socket ${socketPath}`);
  let closing = false;
  const stop = () => {
    if (closing) return;
    closing = true;
    const close = server => new Promise(resolve => server.close(resolve));
    const timer = setTimeout(() => {proxy.closeAllConnections();local.closeAllConnections();},5000);
    timer.unref();
    Promise.all([close(proxy),close(local)]).then(() => {clearTimeout(timer);instance.close();});
  };
  process.once('SIGTERM',stop);
  process.once('SIGINT',stop);
  return {proxy,local,stop};
}
