import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {createApp} from '../server.js';

const tokens = {writer:'w'.repeat(43),reader:'r'.repeat(43),admin:'a'.repeat(43),expired:'e'.repeat(43)};
const entries = () => Object.entries(tokens).map(([id,token]) => ({id,
 tokenHash:createHash('sha256').update(token).digest('hex'),
 scopes:id==='writer'?['upload']:id==='reader'?['read']:['read','upload','delete'],
 ...(id==='expired'?{expiresAt:'2000-01-01T00:00:00Z'}:{})}));

async function fixture(t,options={}) {
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'pigeon-security-'));
 const config=path.join(dir,'agents.json');
 fs.writeFileSync(config,JSON.stringify(entries()),{mode:0o600});
 const instance=createApp({dataDir:dir,agentTokensFile:config,owner:'owner@example.com',publicUrl:'https://pigeon.example',minFreeBytes:1,...options});
 const server=instance.app.listen(0,'127.0.0.1');
 await new Promise(r=>server.once('listening',r));
 t.after(async()=>{await new Promise(r=>server.close(r));instance.close();fs.rmSync(dir,{recursive:true,force:true});});
 const request=async(route,options={})=>{
  const base=`http://127.0.0.1:${server.address().port}`;
  const prepared=new Request(base+route,options);
  const body=options.body?Buffer.from(await prepared.arrayBuffer()):undefined;
  return new Promise((resolve,reject)=>{
   const req=http.request(base+route,{method:options.method||'GET',headers:{...Object.fromEntries(prepared.headers),host:options.headers?.host||'localhost:8787',...(body?{'content-length':body.length}:{})}},res=>{
    const chunks=[];res.on('data',c=>chunks.push(c));res.on('end',()=>resolve(new Response(res.statusCode===204?null:Buffer.concat(chunks),{status:res.statusCode,headers:res.headers})));
   });req.on('error',reject);req.end(body);
  });
 };
 const auth=(id='writer')=>({authorization:`Bearer ${tokens[id]}`});
 const upload=(body='report',id='writer',name='report.txt')=>{
  const form=new FormData();form.append('file',new Blob([body]),name);
  return request('/api/files',{method:'POST',headers:auth(id),body:form});
 };
 return {dir,config,request,upload,auth,server};
}

test('TCP rejects anonymous and forged Tailscale identities on every route',async t=>{
 const f=await fixture(t);
 for (const route of ['/','/api/files','/files/example','/app.js']) {
  for (const host of ['localhost:8787','127.0.0.1:8787','pigeon.example']) {
   assert.equal((await f.request(route,{headers:{host,'tailscale-user-login':'owner@example.com','x-forwarded-for':'100.64.0.1'}})).status,403);
  }
 }
 assert.equal((await f.request('/api/files')).status,403);
 assert.equal((await f.request('/api/files',{method:'POST',headers:{'X-Pigeon-Request':'1'}})).status,403);
 assert.equal((await f.request('/api/files',{headers:{authorization:'Bearer bad'}})).status,403);
 assert.equal((await f.request('/api/files',{headers:f.auth('expired')})).status,403);
 assert.equal((await f.request('/api/files',{headers:{...f.auth('admin'),host:'evil.example'}})).status,403);
});

test('tokens enforce read/upload/delete scopes and revocation is immediate',async t=>{
 const f=await fixture(t);
 const result=await f.upload();assert.equal(result.status,201);const file=await result.json();
 for (const route of ['/api/files',`/api/files/${file.id}`,`/api/files/${file.id}/raw`,`/api/files/${file.id}/download`,`/api/files/${file.id}/content`]) {
  assert.equal((await f.request(route,{headers:f.auth()})).status,403);
  assert.equal((await f.request(route,{headers:f.auth('reader')})).status,200);
 }
 assert.equal((await f.upload('bad','reader')).status,403);
 assert.equal((await f.request(`/api/files/${file.id}`,{method:'DELETE',headers:f.auth()})).status,403);
 assert.equal((await f.request(`/api/files/${file.id}`,{method:'DELETE',headers:f.auth('admin')})).status,204);
 fs.writeFileSync(f.config,JSON.stringify(entries().filter(a=>a.id!=='writer')));
 assert.equal((await f.upload()).status,403);
 assert.equal((await f.request('/api/files',{headers:f.auth('reader')})).status,200);
 fs.writeFileSync(f.config,'invalid json');
 assert.equal((await f.upload()).status,503);
});

test('quota counts existing and orphan files and cleans rejected temporary uploads',async t=>{
 const f=await fixture(t,{maxStorageBytes:12});
 fs.writeFileSync(path.join(f.dir,'blobs','orphan'),'1234');
 const result=await f.upload('1234');assert.equal(result.status,201);const file=await result.json();
 assert.equal((await f.upload('12345')).status,507);
 assert.deepEqual(fs.readdirSync(path.join(f.dir,'tmp')),[]);
 assert.equal((await f.request(`/api/files/${file.id}`,{method:'DELETE',headers:f.auth('admin')})).status,204);
 assert.equal((await f.upload('12345')).status,201);
});

test('file count blocks uploads but leaves reads and deletion usable',async t=>{
 const f=await fixture(t,{maxFiles:1});
 const file=await (await f.upload()).json();
 assert.equal((await f.upload()).status,507);
 assert.equal((await f.request('/api/files',{headers:f.auth('reader')})).status,200);
 assert.equal((await f.request(`/api/files/${file.id}`,{method:'DELETE',headers:f.auth('admin')})).status,204);
 assert.equal((await f.upload()).status,201);
});

test('global rate limit includes malformed uploads and is not bypassed by another token',async t=>{
 const f=await fixture(t,{uploadsPerMinute:2});
 assert.equal((await f.upload('bad','writer','bad.exe')).status,415);
 assert.equal((await f.upload()).status,201);
 const response=await f.upload('another','admin');
 assert.equal(response.status,429);assert.ok(Number(response.headers.get('retry-after'))>0);
 assert.equal((await f.request('/api/files',{headers:f.auth('reader')})).status,200);
});

test('free disk reserve denies uploads before writing',async t=>{
 const f=await fixture(t,{minFreeBytes:Number.MAX_SAFE_INTEGER});
 assert.equal((await f.upload()).status,507);
 assert.deepEqual(fs.readdirSync(path.join(f.dir,'tmp')),[]);
});

test('concurrent upload rejected; abort cleans partial file and releases slot',async t=>{
 const f=await fixture(t);
 const req=http.request({host:'127.0.0.1',port:f.server.address().port,path:'/api/files',method:'POST',headers:{host:'localhost:8787',...f.auth(),'content-type':'multipart/form-data; boundary=demo'}});
 req.on('error',()=>{});
 req.write('--demo\r\nContent-Disposition: form-data; name="file"; filename="report.txt"\r\nContent-Type: text/plain\r\n\r\npartial');
 // Wait for the first upload to actually open its temporary file.
 for(let i=0;i<100 && !fs.readdirSync(path.join(f.dir,'tmp')).length;i++) await new Promise(r=>setTimeout(r,10));
 assert.equal(fs.readdirSync(path.join(f.dir,'tmp')).length,1);
 assert.equal((await f.upload()).status,429);
 req.destroy();
 for(let i=0;i<100 && fs.readdirSync(path.join(f.dir,'tmp')).length;i++) await new Promise(r=>setTimeout(r,10));
 assert.deepEqual(fs.readdirSync(path.join(f.dir,'tmp')),[]);
 assert.equal((await f.upload()).status,201);
});

test('invalid limits fail startup',()=>{
 for(const value of [0,-1,'abc',1.5]) assert.throws(()=>createApp({maxFiles:value}),/positive integer/);
});
