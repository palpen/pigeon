import fs from 'node:fs';
import {randomBytes,createHash} from 'node:crypto';
import {readAgents} from '../security.js';

const [id,scopesText,configFile,tokenFile] = process.argv.slice(2);
if (!id || !scopesText || !configFile || !tokenFile || !/^[\w-]{1,64}$/.test(id) ||
    scopesText.split(',').some(s => !['read','upload','delete'].includes(s))) {
  console.error('Usage: node scripts/add-agent.js ID upload[,read,delete] /private/agents.json /private/agent.token');
  process.exit(2);
}
const agents = fs.existsSync(configFile) ? readAgents(configFile) : [];
if (agents.some(a => a.id === id)) throw new Error('Agent ID already exists. Remove the old entry first to rotate it.');
const token = randomBytes(32).toString('base64url');
fs.writeFileSync(tokenFile,token+'\n',{mode:0o600,flag:'wx'});
agents.push({id,scopes:scopesText.split(','),tokenHash:createHash('sha256').update(token).digest('hex')});
const temporary = configFile+'.'+randomBytes(8).toString('hex')+'.tmp';
fs.writeFileSync(temporary,JSON.stringify(agents,null,2)+'\n',{mode:0o600,flag:'wx'});
fs.renameSync(temporary,configFile);
console.log('Agent configured. Token saved to the requested private file; no token was printed.');
