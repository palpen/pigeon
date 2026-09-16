import fs from 'node:fs';
import path from 'node:path';
import {createHash, timingSafeEqual} from 'node:crypto';

export function positiveInteger(value, name) {
  if (!['number','string'].includes(typeof value) || !/^\d+$/.test(String(value))) throw new Error(`${name} must be a positive integer.`);
  const n = Number(value);
  if (!Number.isSafeInteger(n) || n <= 0) throw new Error(`${name} must be a positive integer.`);
  return n;
}

export function privateDirectory(directory) {
  const stat = fs.lstatSync(directory);
  if (!stat.isDirectory() || stat.uid !== process.getuid() || (stat.mode & 0o077)) {
    throw new Error('Directory must be private, owned by the service user, and not a symlink.');
  }
}

export function validExpiry(value) {
  return typeof value === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{3})?Z$/.test(value) &&
    Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === (value.length === 20 ? value.replace('Z', '.000Z') : value);
}

export function validateAgents(agents) {
  const ids = new Set(), hashes = new Set();
  if (!Array.isArray(agents) || agents.length > 100) throw new Error('Invalid agent token configuration.');
  for (const a of agents) {
    if (!a || typeof a.id !== 'string' || !/^[\w-]{1,64}$/.test(a.id) || ids.has(a.id) ||
        typeof a.tokenHash !== 'string' || !/^[a-f0-9]{64}$/.test(a.tokenHash) || hashes.has(a.tokenHash) ||
        !Array.isArray(a.scopes) || !a.scopes.length || new Set(a.scopes).size !== a.scopes.length || a.scopes.some(s => !['read','upload','delete'].includes(s)) ||
        (a.expiresAt !== undefined && !validExpiry(a.expiresAt))) {
      throw new Error('Invalid agent token configuration.');
    }
    ids.add(a.id); hashes.add(a.tokenHash);
  }
  return agents;
}

// Store only hashes and reload for each token request. Parse failures must never
// expose file contents or fall back to owner access.
export function readAgents(filename) {
  if (filename === undefined) return [];
  let fd;
  try {
    if (!path.isAbsolute(filename)) throw new Error();
    privateDirectory(path.dirname(filename));
    fd = fs.openSync(filename, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
    const stat = fs.fstatSync(fd);
    if (!stat.isFile() || stat.uid !== process.getuid() || (stat.mode & 0o777) !== 0o600 || stat.size > 128 * 1024) throw new Error();
    return validateAgents(JSON.parse(fs.readFileSync(fd, 'utf8')));
  } catch {
    // JSON parse errors can contain credentials. Never propagate file contents.
    throw new Error('Agent token registry is unavailable or invalid; require private directories and a mode-0600 regular file.');
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

export function authenticateAgent(header, agents) {
  const match = /^Bearer ([A-Za-z0-9_-]{32,256})$/.exec(header);
  if (!match) return undefined;
  const digest = createHash('sha256').update(match[1]).digest();
  return agents.find(a => timingSafeEqual(digest, Buffer.from(a.tokenHash, 'hex')) &&
    (!a.expiresAt || Date.parse(a.expiresAt) > Date.now()));
}
