import {createHash} from 'node:crypto';
import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {createApp} from '../server.js';

export const tokens = {writer:'w'.repeat(43),reader:'r'.repeat(43),admin:'a'.repeat(43),expired:'e'.repeat(43)};
export const entries = () => Object.entries(tokens).map(([id,token]) => ({id,
 tokenHash:createHash('sha256').update(token).digest('hex'),
 scopes:id==='writer'?['upload']:id==='reader'?['read']:['read','upload','delete'],
 ...(id==='expired'?{expiresAt:'2000-01-01T00:00:00Z'}:{})}));

export async function fixture(t,options={}) {
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'pigeon-security-'));
 const config=path.join(dir,'agents.json');
 fs.writeFileSync(config,JSON.stringify(entries()),{mode:0o600});
 const instance=createApp({dataDir:dir,agentTokensFile:config,owner:'owner@example.com',publicUrl:'https://pigeon.example',minFreeBytes:1,...options});
 const server=http.createServer(instance.app).listen(0,'127.0.0.1');
 await new Promise(r=>server.once('listening',r));
 const socketPath=path.join(dir,'test.sock');
 const proxy=http.createServer(instance.proxyHandler).listen(socketPath);
 await new Promise(r=>proxy.once('listening',r));
 t.after(async()=>{await Promise.all([new Promise(r=>server.close(r)),new Promise(r=>proxy.close(r))]);await instance.close();fs.rmSync(dir,{recursive:true,force:true});});
 const request=async(route,options={})=>{
  const base=`http://127.0.0.1:${server.address().port}`;
  const prepared=new Request(base+route,options);
  const body=options.body?Buffer.from(await prepared.arrayBuffer()):undefined;
  return new Promise((resolve,reject)=>{
   const req=http.request(base+route,{agent:false,...(options.unix?{socketPath}:{}),method:options.method||'GET',headers:{...Object.fromEntries(prepared.headers),host:options.headers?.host||(options.unix?'pigeon.example':`localhost:${server.address().port}`),...(body?{'content-length':body.length}:{})}},res=>{
    const chunks=[];res.on('data',c=>chunks.push(c));res.on('end',()=>resolve(new Response(res.statusCode===204||options.method==='HEAD'?null:Buffer.concat(chunks),{status:res.statusCode,headers:res.headers})));
   });req.on('error',reject);req.end(body);
  });
 };
 const auth=(id='writer')=>({authorization:`Bearer ${tokens[id]}`});
 const upload=(body='report',id='writer',name='report.txt')=>{
  const form=new FormData();form.append('file',new Blob([body]),name);
  return request('/api/files',{method:'POST',headers:auth(id),body:form});
 };
 return {dir,config,request,upload,auth,server,proxy,instance,socketPath};
}
