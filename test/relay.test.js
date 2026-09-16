import {test} from 'node:test';
import http from 'node:http';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {createApp} from '../server.js';

test('upload, sanitize, isolate, persist, retrieve and delete files',async()=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'relay-test-'));
 const socketPath=path.join(dir,'test.sock');
 let instance=createApp({dataDir:dir,owner:'owner@example.com',publicUrl:'https://relay.example:8443'});
 let server=http.createServer(instance.proxyHandler).listen(socketPath);await new Promise(r=>server.once('listening',r));
 const base='http://localhost:8787';
 const request=async(url,options={})=>{
   const prepared=new Request(base+url,{...options,headers:{'X-Pigeon-Request':'1','tailscale-user-login':'owner@example.com',...options.headers}});
   const body=options.body?Buffer.from(await prepared.arrayBuffer()):undefined;
   return new Promise((resolve,reject)=>{const req=http.request(base+url,{socketPath,agent:false,method:options.method||'GET',headers:{...Object.fromEntries(prepared.headers),host:options.headers?.host||'localhost:8787',...(body?{'content-length':body.length}:{})}},res=>{const chunks=[];res.on('data',c=>chunks.push(c));res.on('end',()=>resolve(new Response(res.statusCode===204?null:Buffer.concat(chunks),{status:res.statusCode,headers:res.headers})));});req.on('error',reject);req.end(body);});
 };
 try {
  assert.equal((await request('/api/files',{headers:{host:'evil.example'}})).status,403);
  assert.equal((await request('/api/files',{headers:{host:'relay.example:8443','tailscale-user-login':''}})).status,403);
  assert.equal((await request('/api/files',{headers:{host:'relay.example:8443','tailscale-user-login':'other@example.com'}})).status,403);
  assert.equal((await request('/api/files',{headers:{host:'relay.example:8443','tailscale-user-login':'owner@example.com'}})).status,200);
  assert.equal((await request('/api/files',{method:'POST',headers:{origin:'https://evil.example'}})).status,403);
  assert.equal((await request('/api/files',{method:'POST',headers:{'X-Pigeon-Request':''}})).status,403);
  const content='# Report\n\n| A | B |\n|---|---|\n| 1 | 2 |\n\n<script>alert(1)</script><img src="x" onerror="alert(1)">\n\n[bad](javascript:alert)\n\n- [x] Done';
  const upload=async(name,body)=>{const form=new FormData();form.append('file',new Blob([body]),name);return request('/api/files',{method:'POST',body:form});};
  assert.equal((await request('/api/files',{method:'POST',headers:{'X-Pigeon-Request':'','X-Relay-Request':'1'}})).status,400);
  const result=await upload('report.md',content);assert.equal(result.status,201,await result.clone().text());const file=await result.json();
  assert.match(file.url,/^https:\/\/relay.example:8443\/files\//);
  const rendered=await (await request(`/api/files/${file.id}/content`)).json();assert.match(rendered.html,/<h1>Report<\/h1>/);assert.match(rendered.html,/<table>/);assert.doesNotMatch(rendered.html,/<script|onerror|javascript:/);assert.match(rendered.html,/checked/);
  assert.equal(await (await request(`/api/files/${file.id}/download`)).text(),content);
  assert.equal((await upload('bad.html','<script>bad()</script>')).status,415);
  for(const [name,content] of [['image.png',Buffer.from('89504e470d0a1a0a','hex')],['document.pdf','%PDF-1.4\n%%EOF'],['note.txt','hello']]){const r=await upload(name,content);assert.equal(r.status,201);const f=await r.json();assert.equal((await request(`/api/files/${f.id}/raw`)).status,200);}
  assert.equal((await (await request('/api/files')).json()).files.length,4);
  await new Promise(r=>server.close(r));await instance.close();
  instance=createApp({dataDir:dir,owner:'owner@example.com'});server=http.createServer(instance.proxyHandler).listen(socketPath);await new Promise(r=>server.once('listening',r));
  assert.equal((await (await request('/api/files')).json()).files.length,4);
  assert.equal((await request(`/api/files/${file.id}`,{method:'DELETE'})).status,204);
  assert.equal((await request(`/api/files/${file.id}`)).status,404);
  assert.equal(fs.existsSync(path.join(dir,'blobs',file.id)),false);
 }finally{await new Promise(r=>server.close(r));await instance.close();fs.rmSync(dir,{recursive:true,force:true});}
});
