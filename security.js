import fs from 'node:fs';
import {createHash, timingSafeEqual} from 'node:crypto';

export function positiveInteger(value, name) {
  const n = Number(value);
  if (!Number.isSafeInteger(n) || n <= 0) throw new Error(`${name} must be a positive integer.`);
  return n;
}

// Store only hashes on the server. Reload on each request so removal revokes access
// without a restart. An unreadable/invalid file must never fall back to owner access.
export function readAgents(filename) {
  if (!filename) return [];
  const stat = fs.lstatSync(filename);
  if (!stat.isFile() || (stat.mode & 0o077)) throw new Error('Agent token file must be a regular file with mode 0600.');
  const agents = JSON.parse(fs.readFileSync(filename, 'utf8'));
  const ids = new Set(), hashes = new Set();
  if (!Array.isArray(agents) || agents.length > 100) throw new Error('Invalid agent token configuration.');
  for (const a of agents) {
    if (!a || typeof a.id !== 'string' || !/^[\w-]{1,64}$/.test(a.id) || ids.has(a.id) ||
        typeof a.tokenHash !== 'string' || !/^[a-f0-9]{64}$/.test(a.tokenHash) || hashes.has(a.tokenHash) ||
        !Array.isArray(a.scopes) || !a.scopes.length || a.scopes.some(s => !['read','upload','delete'].includes(s)) ||
        (a.expiresAt !== undefined && (typeof a.expiresAt !== 'string' || !Number.isFinite(Date.parse(a.expiresAt))))) {
      throw new Error('Invalid agent token configuration.');
    }
    ids.add(a.id); hashes.add(a.tokenHash);
  }
  return agents;
}

export function authenticateAgent(header, agents) {
  const match = /^Bearer ([A-Za-z0-9_-]{32,256})$/.exec(header);
  if (!match) return undefined;
  const digest = createHash('sha256').update(match[1]).digest();
  return agents.find(a => timingSafeEqual(digest, Buffer.from(a.tokenHash, 'hex')) &&
    (!a.expiresAt || Date.parse(a.expiresAt) > Date.now()));
}
