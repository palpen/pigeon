import {test} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import net from 'node:net';
import http from 'node:http';
import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {start} from '../start.js';
import {createApp} from '../server.js';

const serverFile=fileURLToPath(new URL('../server.js',import.meta.url));
function directory(t) {
  const dir=fs.mkdtempSync(path.join(process.platform === 'darwin' ? '/private/tmp' : os.tmpdir(), 'pgn-'));
  t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
  return dir;
}
async function boot(t,dir,options={}) {
  const app=await start({dataDir:dir,port:0,handleSignals:false,owner:'owner@example.com',publicUrl:'https://pigeon.example',minFreeBytes:1,...options});
  t.after(()=>app.stop());
  return app;
}
function request(app,route='/',options={}) {
  const {unix=false,...rest}=options;
  return new Promise((resolve,reject)=>{
    const req=http.request({host:'127.0.0.1',port:app.local.address().port,...(unix?{socketPath:app.socketPath}:{}),agent:false,path:route,...rest,
      headers:{host:'pigeon.example','tailscale-user-login':'owner@example.com','x-pigeon-request':'1',...rest.headers}},res=>{
        const chunks=[];res.on('data',c=>chunks.push(c));res.on('end',()=>resolve({status:res.statusCode,body:Buffer.concat(chunks).toString()}));
      });req.on('error',reject);req.end(options.body);
  });
}
function childServer(t,dir) {
  const child=spawn(process.execPath,[serverFile],{env:{...process.env,DATA_DIR:dir,PORT:'0',OWNER_LOGIN:'owner@example.com',PUBLIC_URL:'https://pigeon.example',MIN_FREE_DISK_BYTES:'1'},stdio:['ignore','pipe','pipe']});
  let output='',errors='';child.stdout.on('data',c=>output+=c);child.stderr.on('data',c=>errors+=c);
  const exited=new Promise(resolve=>child.once('exit',(code,signal)=>resolve({code,signal,output,errors})));
  const ready=new Promise((resolve,reject)=>{
    const timer=setTimeout(()=>{child.kill('SIGKILL');reject(new Error('Server startup timed out.'));},5000);
    child.stdout.on('data',()=>{const match=output.match(/127\.0\.0\.1:(\d+);/);if(match){clearTimeout(timer);resolve(Number(match[1]));}});
    child.once('exit',()=>{clearTimeout(timer);reject(new Error('Server exited before listening: '+errors));});
  });
  ready.catch(()=>{});
  t.after(async()=>{if(child.exitCode===null && child.signalCode===null){child.kill('SIGKILL');await exited;}});
  return {child,ready,exited};
}

test('startup binds token-only TCP and owner Unix listeners with private permissions',async t=>{
  const dir=directory(t), app=await boot(t,dir);
  assert.equal(app.local.address().address,'127.0.0.1');
  assert.equal(fs.statSync(app.socketPath).mode&0o777,0o600);
  assert.equal(fs.statSync(path.dirname(app.socketPath)).mode&0o777,0o700);
  assert.equal((await request(app,'/api/files')).status,403);
  assert.equal((await request(app,'/api/files',{unix:true})).status,200);
  await Promise.all([app.stop(),app.stop()]);
  assert.equal(fs.existsSync(app.socketPath),false);
  const next=await boot(t,dir);assert.equal((await request(next,'/api/files',{unix:true})).status,200);
});

test('same-process and simultaneous starts cannot acquire a second data writer',async t=>{
  const dir=directory(t);
  const results=await Promise.allSettled([boot(t,dir),boot(t,dir)]);
  assert.equal(results.filter(r=>r.status==='fulfilled').length,1);
  assert.match(results.find(r=>r.status==='rejected').reason.message,/locked/);
  assert.throws(()=>createApp({dataDir:dir}),/locked/);
  const first=results.find(r=>r.status==='fulfilled').value;
  assert.equal((await request(first,'/api/files',{unix:true})).status,200);
});

test('cross-process simultaneous startup has one winner and cannot unlink its socket',async t=>{
  const dir=directory(t),one=childServer(t,dir),two=childServer(t,dir);
  const results=await Promise.allSettled([one.ready,two.ready]);
  assert.equal(results.filter(r=>r.status==='fulfilled').length,1);
  const loser=results[0].status==='rejected'?one:two;
  assert.equal((await loser.exited).code,1);
  const socket=path.join(dir,'run','pigeon.sock');assert.equal(fs.statSync(socket).isSocket(),true);
  const winner=results[0].status==='fulfilled'?one:two;
  winner.child.kill('SIGTERM');assert.equal((await winner.exited).code,0);
  assert.equal(fs.existsSync(socket),false);
});

test('SIGKILL recovery releases the OS lock and replaces a stale socket',async t=>{
  const dir=directory(t), first=childServer(t,dir);await first.ready;
  const socket=path.join(dir,'run','pigeon.sock');
  first.child.kill('SIGKILL');await first.exited;
  assert.equal(fs.lstatSync(socket).isSocket(),true);
  const next=await boot(t,dir);assert.equal((await request(next,'/api/files',{unix:true})).status,200);
});

test('startup refuses live sockets, regular files and symlinks without removing them',async t=>{
  const dir=directory(t),run=path.join(dir,'run'),socket=path.join(run,'pigeon.sock');
  fs.mkdirSync(run,{mode:0o700});
  for(const kind of ['file','symlink','live']) {
    let listener;
    if(kind==='file')fs.writeFileSync(socket,'keep');
    if(kind==='symlink')fs.symlinkSync(path.join(dir,'missing'),socket);
    if(kind==='live') {listener=net.createServer(c=>c.end()).listen(socket);await new Promise(r=>listener.once('listening',r));}
    const before=fs.lstatSync(socket);
    await assert.rejects(start({dataDir:dir,port:0,handleSignals:false}),kind==='live'?/in use/:/non-socket/);
    assert.equal(fs.lstatSync(socket).ino,before.ino);
    if(listener)await new Promise(r=>listener.close(r));else fs.unlinkSync(socket);
  }
  await boot(t,dir);
});

test('occupied TCP port and invalid configuration release socket and data lock',async t=>{
  const dir=directory(t),listener=net.createServer().listen(0,'127.0.0.1');
  await new Promise(r=>listener.once('listening',r));
  t.after(()=>new Promise(r=>listener.close(r)));
  await assert.rejects(start({dataDir:dir,port:listener.address().port,handleSignals:false}),{code:'EADDRINUSE'});
  assert.equal(fs.existsSync(path.join(dir,'run','pigeon.sock')),false);
  for(const port of [-1,65536,1.5,'bad']) await assert.rejects(start({dataDir:dir,port,handleSignals:false}),/PORT/);
  await assert.rejects(start({dataDir:dir,port:0,maxFiles:0,handleSignals:false}),/positive integer/);
  await boot(t,dir);
});

test('private directory and symlink checks protect socket and database paths',async t=>{
  for(const kind of ['run-mode','run-link','blob-link','database-link','lock-link','data-mode']) {
    const dir=directory(t),outside=directory(t);
    if(kind==='run-mode')fs.mkdirSync(path.join(dir,'run'),{mode:0o755});
    if(kind==='run-link')fs.symlinkSync(outside,path.join(dir,'run'));
    if(kind==='blob-link')fs.symlinkSync(outside,path.join(dir,'blobs'));
    if(kind==='database-link')fs.symlinkSync(path.join(outside,'missing'),path.join(dir,'relay.sqlite'));
    if(kind==='lock-link')fs.symlinkSync(path.join(outside,'missing'),path.join(dir,'.pigeon-lock.sqlite'));
    if(kind==='data-mode')fs.chmodSync(dir,0o755);
    await assert.rejects(start({dataDir:dir,port:0,handleSignals:false}));
    assert.deepEqual(fs.readdirSync(outside),[]);
  }
});

test('quotas survive process restart, including orphan files',async t=>{
  const dir=directory(t),app=await boot(t,dir,{maxStorageBytes:10,maxFiles:3});
  const body='--d\r\nContent-Disposition: form-data; name="file"; filename="a.txt"\r\n\r\n123456\r\n--d--\r\n';
  const options={unix:true,method:'POST',headers:{'content-type':'multipart/form-data; boundary=d','content-length':Buffer.byteLength(body)},body};
  const uploaded=await request(app,'/api/files',options);assert.equal(uploaded.status,201);
  fs.writeFileSync(path.join(dir,'tmp','crash'),'1234');
  await app.stop();
  const next=await boot(t,dir,{maxStorageBytes:10,maxFiles:3});
  assert.equal((await request(next,'/api/files',options)).status,507);
  const id=JSON.parse(uploaded.body).id;
  assert.equal((await request(next,`/api/files/${id}`,{unix:true,method:'DELETE'})).status,204);
  assert.equal((await request(next,'/api/files',options)).status,201);
});

test('shutdown aborts a stalled upload before releasing its data lock',async t=>{
  const dir=directory(t),app=await boot(t,dir);
  const req=http.request({socketPath:app.socketPath,agent:false,path:'/api/files',method:'POST',headers:{host:'pigeon.example','tailscale-user-login':'owner@example.com','x-pigeon-request':'1','content-type':'multipart/form-data; boundary=stop'}});
  req.on('error',()=>{});
  req.write('--stop\r\nContent-Disposition: form-data; name="file"; filename="a.txt"\r\n\r\npartial');
  for(let i=0;i<100 && !fs.readdirSync(path.join(dir,'tmp')).length;i++)await new Promise(r=>setTimeout(r,10));
  assert.equal(fs.readdirSync(path.join(dir,'tmp')).length,1);
  const stopping=app.stop();
  assert.throws(()=>createApp({dataDir:dir}),/locked/);
  await stopping;
  assert.deepEqual(fs.readdirSync(path.join(dir,'tmp')),[]);
  const next=await boot(t,dir);assert.equal((await request(next,'/api/files',{unix:true})).status,200);
});
