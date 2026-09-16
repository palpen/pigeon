import {test} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {addAgent} from '../scripts/add-agent.js';
import {readAgents} from '../security.js';
import {fixture} from '../support/fixture.js';

const addScript=fileURLToPath(new URL('../scripts/add-agent.js',import.meta.url));
const uploadScript=fileURLToPath(new URL('../scripts/upload.sh',import.meta.url));
function run(command,args,env={}) {
  return new Promise((resolve,reject)=>{
    const child=spawn(command,args,{env:{...process.env,...env},stdio:['ignore','pipe','pipe']});
    let stdout='',stderr='';child.stdout.on('data',c=>stdout+=c);child.stderr.on('data',c=>stderr+=c);
    child.on('error',reject);child.on('exit',code=>resolve({code,stdout,stderr}));
  });
}
function paths(t) {
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'agent-'));
  t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
  return {dir,configFile:path.join(dir,'agents.json'),tokenFile:path.join(dir,'agent "one".token')};
}

test('token CLI creates a private hash registry, optional expiry and never prints secrets',async t=>{
  const p=paths(t),expiry='2099-01-01T00:00:00Z';
  const result=await run(process.execPath,[addScript,'reports','upload',p.configFile,p.tokenFile,expiry]);
  assert.equal(result.code,0,result.stderr);
  const token=fs.readFileSync(p.tokenFile,'utf8').trim();assert.match(token,/^[A-Za-z0-9_-]{43}$/);
  assert.equal(fs.statSync(p.tokenFile).mode&0o777,0o600);assert.equal(fs.statSync(p.configFile).mode&0o777,0o600);
  const [agent]=readAgents(p.configFile);assert.equal(agent.tokenHash,createHash('sha256').update(token).digest('hex'));assert.equal(agent.expiresAt,expiry);
  assert.doesNotMatch(result.stdout+result.stderr,new RegExp(token));assert.ok(!fs.readFileSync(p.configFile,'utf8').includes(token));
  const old=fs.readFileSync(p.configFile,'utf8');
  for(const args of [['another','upload',p.configFile,p.tokenFile],['reports','upload',p.configFile,path.join(p.dir,'different.token')],['bad','upload',p.configFile,path.join(p.dir,'bad.token'),'2000-01-01T00:00:00Z']]) {
    const rejected=await run(process.execPath,[addScript,...args]);assert.equal(rejected.code,2);assert.equal(fs.readFileSync(p.configFile,'utf8'),old);
  }
  assert.equal(fs.readFileSync(p.tokenFile,'utf8').trim(),token);
  assert.equal(fs.existsSync(path.join(p.dir,'different.token')),false);
});

test('token writer serializes concurrent updates and permits a safe retry',async t=>{
  const p=paths(t),a=path.join(p.dir,'a.token'),b=path.join(p.dir,'b.token');
  const results=await Promise.all([run(process.execPath,[addScript,'a','upload',p.configFile,a]),run(process.execPath,[addScript,'b','read',p.configFile,b])]);
  assert.ok(results.some(r=>r.code===0));
  for(const [i,id,scope,file] of [[0,'a','upload',a],[1,'b','read',b]]) {
    if(results[i].code!==0) {
      assert.equal(fs.existsSync(file),false);
      assert.equal((await run(process.execPath,[addScript,id,scope,p.configFile,file])).code,0);
    }
  }
  assert.deepEqual(readAgents(p.configFile).map(a=>a.id).sort(),['a','b']);
  assert.deepEqual(fs.readdirSync(p.dir).sort(),['a.token','agents.json','b.token']);
});

test('token writer cleans partial failure without overwriting prior credentials',t=>{
  const p=paths(t);
  addAgent({...p,id:'first',scopes:['upload']});
  const before=fs.readFileSync(p.configFile,'utf8');
  const tokenFile=path.join(p.dir,'second.token');
  const rename=t.mock.method(fs,'renameSync',()=>{throw new Error('disk failure');});
  assert.throws(()=>addAgent({...p,tokenFile,id:'second',scopes:['read']}));
  rename.mock.restore();
  assert.equal(fs.readFileSync(p.configFile,'utf8'),before);
  assert.equal(fs.existsSync(tokenFile),false);
  assert.deepEqual(fs.readdirSync(p.dir).sort(),['agent "one".token','agents.json']);
  fs.mkdirSync(p.configFile+'.lock',{mode:0o700});
  assert.throws(()=>addAgent({...p,tokenFile,id:'second',scopes:['read']}));
  assert.equal(fs.existsSync(tokenFile),false);
});

test('token writer rejects symlinks, unsafe parents, malformed registries and the entry limit',t=>{
  const p=paths(t);
  fs.writeFileSync(p.configFile,'not-json-private-canary',{mode:0o600});
  assert.throws(()=>addAgent({...p,id:'test',scopes:['upload']}),err=>!err.message.includes('canary'));
  assert.equal(fs.existsSync(p.tokenFile),false);
  fs.unlinkSync(p.configFile);fs.symlinkSync(path.join(p.dir,'missing'),p.configFile);
  assert.throws(()=>addAgent({...p,id:'test',scopes:['upload']}));assert.equal(fs.existsSync(p.tokenFile),false);
  fs.unlinkSync(p.configFile);fs.symlinkSync(path.join(p.dir,'missing'),p.tokenFile);
  assert.throws(()=>addAgent({...p,id:'test',scopes:['upload']}));assert.equal(fs.lstatSync(p.tokenFile).isSymbolicLink(),true);
  fs.unlinkSync(p.tokenFile);fs.chmodSync(p.dir,0o755);
  assert.throws(()=>addAgent({...p,id:'test',scopes:['upload']}));fs.chmodSync(p.dir,0o700);
  const entries=Array.from({length:100},(_,i)=>({id:`agent${i}`,scopes:['upload'],tokenHash:createHash('sha256').update(String(i)).digest('hex')}));
  fs.writeFileSync(p.configFile,JSON.stringify(entries),{mode:0o600});
  assert.throws(()=>addAgent({...p,id:'extra',scopes:['upload']}));assert.equal(readAgents(p.configFile).length,100);assert.equal(fs.existsSync(p.tokenFile),false);
});

test('upload script uses scoped tokens with spaces, quotes and backslashes in paths',async t=>{
  const f=await fixture(t);
  const tokenFile=path.join(f.dir,'token "with spaces".token');
  addAgent({id:'script',scopes:['upload'],configFile:f.config,tokenFile});
  const file=path.join(f.dir,'report "quotes" back\\slash.txt');fs.writeFileSync(file,'script upload');
  const url=`http://127.0.0.1:${f.server.address().port}`;
  for(const env of [{PIGEON_URL:url},{PIGEON_URL:'',RELAY_URL:url}]) {
    const result=await run('/bin/sh',[uploadScript,file],{...env,PIGEON_TOKEN_FILE:tokenFile});
    assert.equal(result.code,0,result.stderr);assert.equal(JSON.parse(result.stdout).size,13);
    assert.ok(!result.stdout.includes(fs.readFileSync(tokenFile,'utf8').trim()));
  }
  for(const value of ['bad','x'.repeat(300),'x'.repeat(43)+'\nAuthorization: hacked']) {
    fs.writeFileSync(tokenFile,value);assert.equal((await run('/bin/sh',[uploadScript,file],{PIGEON_URL:url,PIGEON_TOKEN_FILE:tokenFile})).code,2);
  }
  const denied=await run('/bin/sh',[uploadScript,file],{PIGEON_URL:url,PIGEON_TOKEN_FILE:''});assert.equal(denied.code,22);
});

test('upload script passes the token on stdin, disables curl config, and bounds request time',async t=>{
  const p=paths(t),bin=path.join(p.dir,'bin');fs.mkdirSync(bin,{mode:0o700});
  const curl=path.join(bin,'curl');
  fs.writeFileSync(curl,'#!/bin/sh\nprintf "%s\\n" "$@" > "$CAPTURE_ARGS"\ncat > "$CAPTURE_STDIN"\n',{mode:0o700});
  const token='s'.repeat(43);fs.writeFileSync(p.tokenFile,token+'\n',{mode:0o600});
  const args=path.join(p.dir,'args'),stdin=path.join(p.dir,'stdin');
  const result=await run('/bin/sh',[uploadScript,'report.txt'],{PATH:bin+':'+process.env.PATH,PIGEON_TOKEN_FILE:p.tokenFile,CAPTURE_ARGS:args,CAPTURE_STDIN:stdin});
  assert.equal(result.code,0);
  const argv=fs.readFileSync(args,'utf8');assert.ok(argv.startsWith('--disable\n'));assert.match(argv,/--max-time\n125/);assert.ok(!argv.includes(token));assert.match(argv,/--header\n@-/);
  assert.equal(fs.readFileSync(stdin,'utf8'),`Authorization: Bearer ${token}\n`);
  assert.ok(!result.stdout.includes(token));
});

test('token and registry paths must remain distinct after resolving aliases',t=>{
  const p=paths(t);
  const alias=path.join(p.dir,'alias');fs.symlinkSync(p.dir,alias);
  assert.throws(()=>addAgent({...p,id:'same',scopes:['upload'],tokenFile:path.join(alias,'agents.json')}));
  assert.equal(fs.existsSync(p.configFile),false);
  const sub=path.join(alias,'sub');fs.mkdirSync(sub,{mode:0o700});
  const configFile=path.join(p.dir,'sub','agents.json'),tokenFile=path.join(alias,'sub','agents.json');
  assert.throws(()=>addAgent({configFile,tokenFile,id:'same',scopes:['upload']}),/distinct/);
  assert.equal(fs.existsSync(configFile),false);
});
