import {test} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import os from 'node:os';
import {fixture,entries,tokens} from '../support/fixture.js';
import {readAgents,validExpiry} from '../security.js';
import {createApp} from '../server.js';

for (const unix of [false,true]) {
  test(`${unix?'Unix':'TCP'}: token scopes, HEAD, expiry, revocation and owner fallback`, async t => {
    const f=await fixture(t);
    const ownerHeaders={'tailscale-user-login':'owner@example.com'};
    const result=await f.upload();
    const file=await result.json();
    for (const route of ['/','/app.js','/api/files',`/files/${file.id}`,`/api/files/${file.id}`,`/api/files/${file.id}/content`,`/api/files/${file.id}/raw`,`/api/files/${file.id}/download`]) {
      for (const method of ['GET','HEAD']) {
        assert.equal((await f.request(route,{unix,method,headers:{...ownerHeaders,...f.auth()}})).status,403);
        assert.equal((await f.request(route,{unix,method,headers:f.auth('reader')})).status,200);
      }
    }
    for (const authorization of ['', 'Bearer bad', `Bearer ${'x'.repeat(43)}`, `Bearer ${tokens.expired}`]) {
      assert.equal((await f.request('/api/files',{unix,headers:{...ownerHeaders,authorization}})).status,403);
    }
    for (const [method,route,id] of [['POST','/api/files','reader'],['DELETE',`/api/files/${file.id}`,'reader'],['DELETE',`/api/files/${file.id}`,'writer'],['PATCH','/api/files','admin']]) {
      assert.equal((await f.request(route,{unix,method,headers:{...ownerHeaders,...f.auth(id)}})).status,403);
    }
    fs.writeFileSync(f.config,JSON.stringify(entries().filter(a=>a.id!=='reader')));
    assert.equal((await f.request('/api/files',{unix,headers:{...ownerHeaders,...f.auth('reader')}})).status,403);
    assert.equal((await f.request('/api/files',{unix,headers:ownerHeaders})).status,unix?200:403);
    fs.writeFileSync(f.config,JSON.stringify([{...entries()[0],scopes:['delete']}]));
    assert.equal((await f.request('/api/files',{unix,headers:f.auth()})).status,403);
    assert.equal((await f.request(`/api/files/${file.id}`,{unix,method:'DELETE',headers:f.auth()})).status,204);
    fs.writeFileSync(f.config,'private-canary-not-for-errors');
    const response=await f.request('/api/files',{unix,headers:{...ownerHeaders,...f.auth()}});
    assert.equal(response.status,503);
    assert.doesNotMatch(await response.text(),/canary|tokenHash/);
  });
}

test('Unix owner identity, host and CSRF checks apply to both mutation methods',async t=>{
  const f=await fixture(t);
  const headers={'tailscale-user-login':'owner@example.com','x-pigeon-request':'1',host:'pigeon.example'};
  for(const login of ['', 'other@example.com']) assert.equal((await f.request('/api/files',{unix:true,headers:{...headers,'tailscale-user-login':login}})).status,403);
  for(const method of ['POST','DELETE']) {
    const route=method==='POST'?'/api/files':'/api/files/absent';
    for(const origin of ['https://evil.example','null','http://pigeon.example','https://pigeon.example.evil']) {
      assert.equal((await f.request(route,{unix:true,method,headers:{...headers,origin}})).status,403);
    }
    assert.equal((await f.request(route,{unix:true,method,headers:{...headers,'x-pigeon-request':''}})).status,403);
    for(const marker of ['x-pigeon-request','x-relay-request']) {
      assert.equal((await f.request(route,{unix:true,method,headers:{...headers,'x-pigeon-request':'',[marker]:'1',origin:'https://pigeon.example'}})).status,method==='POST'?400:404);
    }
  }
  assert.equal((await f.request('/api/files',{unix:true,headers:{...headers,host:'evil.example'}})).status,403);
  assert.equal((await f.request('/api/files',{method:'POST',headers:{...f.auth(),origin:'https://evil.example'}})).status,403);
});

test('a Unix socket attached to the ordinary app handler cannot confer owner trust',async t=>{
  const f=await fixture(t);
  const socketPath=path.join(f.dir,'plain.sock');
  const server=http.createServer(f.instance.app).listen(socketPath);
  await new Promise(r=>server.once('listening',r));
  t.after(()=>new Promise(r=>server.close(r)));
  const status=await new Promise((resolve,reject)=>{
    const req=http.get({socketPath,agent:false,path:'/api/files',headers:{host:'pigeon.example','tailscale-user-login':'owner@example.com'}},res=>{res.resume();res.on('end',()=>resolve(res.statusCode));});
    req.on('error',reject);
  });
  assert.equal(status,403);
});

test('registry validation rejects malformed data without exposing contents',()=>{
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'registry-'));
  const file=path.join(dir,'agents.json');
  const a=entries()[0];
  try {
    for(const data of [null,{},[null],[{...a,id:'../bad'}],[a,a],[a,{...a,id:'different'}],[{...a,tokenHash:'bad'}],[{...a,scopes:[]}],[{...a,scopes:['admin']}],[{...a,scopes:['read','read']}],[{...a,expiresAt:'tomorrow'}],[{...a,expiresAt:'2027-02-30T00:00:00Z'}],[{...a,expiresAt:1}],Array(101).fill(a)]) {
      fs.writeFileSync(file,JSON.stringify(data),{mode:0o600});
      assert.throws(()=>readAgents(file),/unavailable or invalid/);
    }
    fs.writeFileSync(file,'secret-canary'.repeat(12000));
    assert.throws(()=>readAgents(file),err=>!err.message.includes('secret-canary'));
    fs.writeFileSync(file,JSON.stringify([a]));
    fs.chmodSync(file,0o644);assert.throws(()=>readAgents(file));fs.chmodSync(file,0o600);
    fs.chmodSync(dir,0o755);assert.throws(()=>readAgents(file));fs.chmodSync(dir,0o700);
    const link=path.join(dir,'link.json');fs.symlinkSync(file,link);assert.throws(()=>readAgents(link));
    fs.unlinkSync(file);assert.throws(()=>readAgents(file));assert.throws(()=>readAgents('relative.json'));assert.throws(()=>readAgents(''));
    assert.deepEqual(readAgents(undefined),[]);
    assert.equal(validExpiry('2027-01-01T00:00:00Z'),true);
    assert.equal(validExpiry('2027-01-01T00:00:00.001Z'),true);
  } finally {fs.rmSync(dir,{recursive:true,force:true});}
});

test('invalid configuration fails before creating data or acquiring a lock',()=>{
  for (const value of [0,-1,'abc',1.5,true,'1e3',Infinity,'']) {
    for (const key of ['maxFiles','maxStorageBytes','uploadsPerMinute','minFreeBytes']) assert.throws(()=>createApp({[key]:value}),/positive integer/);
  }
  for (const publicUrl of ['http://example.com','https://u:password@example.com','https://example.com/path','https://example.com/?a=b','https://example.com/#x','bogus']) assert.throws(()=>createApp({publicUrl}));
});

test('duplicate Authorization headers cannot use owner fallback',async t=>{
  const f=await fixture(t);
  const status=await new Promise((resolve,reject)=>{
    const req=http.get({socketPath:f.socketPath,agent:false,path:'/api/files',headers:{host:'pigeon.example','tailscale-user-login':'owner@example.com',authorization:['Bearer bad',`Bearer ${tokens.admin}`]}},res=>{res.resume();res.on('end',()=>resolve(res.statusCode));});req.on('error',reject);
  });assert.equal(status,403);
});
