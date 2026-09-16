import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {randomBytes,createHash} from 'node:crypto';
import {readAgents, validateAgents, privateDirectory} from '../security.js';

export function addAgent({id, scopes, configFile, tokenFile, expiresAt}) {
  if (!path.isAbsolute(configFile) || !path.isAbsolute(tokenFile) || configFile === tokenFile) throw new Error('Use distinct absolute credential paths.');
  privateDirectory(path.dirname(configFile));
  privateDirectory(path.dirname(tokenFile));
  configFile = path.join(fs.realpathSync(path.dirname(configFile)), path.basename(configFile));
  tokenFile = path.join(fs.realpathSync(path.dirname(tokenFile)), path.basename(tokenFile));
  if (configFile === tokenFile) throw new Error('Use distinct credential paths.');
  const token = randomBytes(32).toString('base64url');
  const entry = {id, scopes, tokenHash:createHash('sha256').update(token).digest('hex'), ...(expiresAt === undefined ? {} : {expiresAt})};
  validateAgents([entry]);
  if (expiresAt && Date.parse(expiresAt) <= Date.now()) throw new Error('Expiry must be in the future.');
  const lock = configFile + '.lock';
  // Never reclaim a lock automatically: a concurrent writer might own it.
  fs.mkdirSync(lock, {mode:0o700});
  const temporary = configFile + '.' + randomBytes(8).toString('hex') + '.tmp';
  let tokenCreated = false, temporaryCreated = false;
  try {
    let agents;
    try { fs.lstatSync(configFile); agents = readAgents(configFile); }
    catch (err) { if (err.code !== 'ENOENT') throw err; agents = []; }
    validateAgents([...agents, entry]);
    const fd = fs.openSync(tokenFile, 'wx', 0o600);
    tokenCreated = true;
    try { fs.writeFileSync(fd, token + '\n'); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
    const configFd = fs.openSync(temporary, 'wx', 0o600);
    temporaryCreated = true;
    try { fs.writeFileSync(configFd, JSON.stringify([...agents, entry],null,2) + '\n'); fs.fsyncSync(configFd); }
    finally { fs.closeSync(configFd); }
    fs.renameSync(temporary, configFile);
    temporaryCreated = false;
    tokenCreated = false;
  } finally {
    try {
      if (temporaryCreated) fs.unlinkSync(temporary);
    } finally {
      try { if (tokenCreated) fs.unlinkSync(tokenFile); }
      finally { fs.rmdirSync(lock); }
    }
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [id,scopesText,configFile,tokenFile,expiresAt,...extra] = process.argv.slice(2);
  try {
    if (!id || !scopesText || !configFile || !tokenFile || extra.length) throw new Error();
    addAgent({id,scopes:scopesText.split(','),configFile,tokenFile,expiresAt});
    console.log('Agent configured. Token saved to the requested private file; no token was printed.');
  } catch {
    console.error('Could not create agent. Check arguments, private paths, registry validity, duplicate IDs, existing token files, and a concurrent registry writer.');
    console.error('Usage: node scripts/add-agent.js ID upload[,read,delete] /private/agents.json /private/agent.token [YYYY-MM-DDTHH:mm:ssZ]');
    process.exitCode = 2;
  }
}
