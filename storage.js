import fs from 'node:fs';
import path from 'node:path';
import {DatabaseSync} from 'node:sqlite';
import {privateDirectory} from './security.js';

// Keep this inode for the lifetime of the installation. SQLite's OS lock is
// released on crash; unlike deleting stale PID files, recovery cannot steal a
// concurrent starter's lock. Use local storage, never a network filesystem.
export function lockDataDirectory(dataDir) {
  fs.mkdirSync(dataDir, {recursive:true, mode:0o700});
  privateDirectory(dataDir);
  const filename = path.join(dataDir, '.pigeon-lock.sqlite');
  const fd = fs.openSync(filename, fs.constants.O_CREAT | fs.constants.O_RDWR | fs.constants.O_NOFOLLOW, 0o600);
  try {
    const stat = fs.fstatSync(fd);
    if (!stat.isFile() || stat.uid !== process.getuid() || (stat.mode & 0o077)) throw new Error('Unsafe data lock file.');
  } finally { fs.closeSync(fd); }
  const lock = new DatabaseSync(filename);
  try {
    lock.exec('PRAGMA locking_mode=EXCLUSIVE; BEGIN EXCLUSIVE; CREATE TABLE IF NOT EXISTS singleton (id INTEGER PRIMARY KEY)');
  } catch {
    lock.close();
    throw new Error('Data directory is locked or unavailable; another Pigeon process may be running.');
  }
  return () => lock.close();
}
