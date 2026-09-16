import {test} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import {Writable} from 'node:stream';
import {DatabaseSync} from 'node:sqlite';
import {fixture} from '../support/fixture.js';
import {MAX_UPLOAD_BYTES} from '../uploads.js';

const pause=ms=>new Promise(r=>setTimeout(r,ms));
async function until(check) { for(let i=0;i<200;i++) { if(check())return;await pause(10); } assert.ok(check(),'condition did not become true'); }
const empty=f=>assert.deepEqual(fs.readdirSync(path.join(f.dir,'tmp')),[]);
function streaming(f) {
  const request=http.request({host:'127.0.0.1',port:f.server.address().port,path:'/api/files',method:'POST',headers:{host:`localhost:${f.server.address().port}`,...f.auth(),'content-type':'multipart/form-data; boundary=demo'}});
  request.on('error',()=>{});
  request.write('--demo\r\nContent-Disposition: form-data; name="file"; filename="report.txt"\r\nContent-Type: text/plain\r\n\r\npartial');
  return request;
}

test('50 MiB limit accepts just below and exact, rejects above with no partial files',async t=>{
  const f=await fixture(t,{uploadsPerMinute:100});
  for(const size of [MAX_UPLOAD_BYTES-1,MAX_UPLOAD_BYTES,MAX_UPLOAD_BYTES+1]) {
    const r=await f.upload(Buffer.alloc(size));
    assert.equal(r.status,size>MAX_UPLOAD_BYTES?413:201);
    if(r.status===201)assert.equal((await r.json()).size,size);
    empty(f);
  }
});

test('quota accepts exact remaining bytes and accounts for temporary orphans',async t=>{
  const f=await fixture(t,{maxStorageBytes:10});
  fs.writeFileSync(path.join(f.dir,'tmp','crash-partial'),'1234');
  assert.equal((await f.upload('1234567')).status,507);
  assert.deepEqual(fs.readdirSync(path.join(f.dir,'tmp')),['crash-partial']);
  const response=await f.upload('123456');assert.equal(response.status,201);
  assert.equal((await f.upload('x')).status,507);
  const file=await response.json();
  assert.equal((await f.request(`/api/files/${file.id}`,{method:'DELETE',headers:f.auth('admin')})).status,204);
  assert.equal((await f.upload('12345')).status,201);
});

test('malformed multipart, fields and duplicate files are rejected and release capacity',async t=>{
  const f=await fixture(t,{uploadsPerMinute:100});
  const badBodies=['--demo\r\nContent-Disposition: form-data; name="file"; filename="a.txt"\r\n\r\npartial', '--demo\r\nnot-a-header\r\n\r\nbody\r\n--demo--\r\n'];
  for(const body of badBodies) {
    const r=await f.request('/api/files',{method:'POST',headers:{...f.auth(),'content-type':'multipart/form-data; boundary=demo'},body});
    assert.equal(r.status,400);empty(f);
  }
  assert.equal((await f.request('/api/files',{method:'POST',headers:{...f.auth(),'content-type':'multipart/form-data'},body:'bad'})).status,400);
  for(const kind of ['fields','duplicate','wrong-name']) {
    const form=new FormData();
    form.append(kind==='wrong-name'?'unexpected':'file',new Blob(['ok']),'report.txt');
    if(kind==='fields')form.append('extra','text');
    if(kind==='duplicate')form.append('file',new Blob(['more']),'second.txt');
    assert.equal((await f.request('/api/files',{method:'POST',headers:f.auth(),body:form})).status,400);empty(f);
  }
  assert.equal((await f.upload()).status,201);
});

test('chunked upload succeeds; timeout removes partial files and releases the slot',async t=>{
  const f=await fixture(t,{uploadTimeoutMs:150});
  const chunked=streaming(f);
  const response=new Promise((resolve,reject)=>{chunked.on('response',r=>{r.resume();r.on('end',()=>resolve(r.statusCode));});chunked.on('error',reject);});
  chunked.end('\r\n--demo--\r\n');assert.equal(await response,201);empty(f);
  const stalled=streaming(f);
  await until(()=>fs.readdirSync(path.join(f.dir,'tmp')).length===1);
  assert.equal((await f.upload()).status,429);
  await until(()=>stalled.destroyed && fs.readdirSync(path.join(f.dir,'tmp')).length===0);
  assert.equal((await f.upload()).status,201);
});

test('rate window resets after one minute and counts rejected attempts',async t=>{
  let now=100000;
  const f=await fixture(t,{uploadsPerMinute:1,now:()=>now});
  assert.equal((await f.upload('bad','writer','bad.exe')).status,415);
  let r=await f.upload();assert.equal(r.status,429);assert.equal(r.headers.get('retry-after'),'60');
  now+=59999;r=await f.upload();assert.equal(r.status,429);assert.equal(r.headers.get('retry-after'),'1');
  now++;assert.equal((await f.upload()).status,201);
});

test('failed disk, rename and SQLite writes clean files and release the upload slot',async t=>{
  const f=await fixture(t,{uploadsPerMinute:100});
  const realCreate=fs.createWriteStream;
  const write=t.mock.method(fs,'createWriteStream',(filename,options)=>filename.startsWith(path.join(f.dir,'tmp'))?
    new Writable({write(chunk,encoding,done){done(Object.assign(new Error('disk canary secret'),{code:'ENOSPC'}));}}):realCreate(filename,options));
  let r=await f.upload();assert.equal(r.status,507);assert.doesNotMatch(await r.text(),/canary/);empty(f);write.mock.restore();
  const rename=t.mock.method(fs,'renameSync',()=>{throw new Error('rename canary secret');});
  r=await f.upload();assert.equal(r.status,500);assert.doesNotMatch(await r.text(),/canary/);empty(f);rename.mock.restore();
  const db=new DatabaseSync(path.join(f.dir,'relay.sqlite'));
  try {
    db.exec("CREATE TRIGGER reject_insert BEFORE INSERT ON files BEGIN SELECT RAISE(ABORT, 'database canary secret'); END");
    r=await f.upload();assert.equal(r.status,500);assert.doesNotMatch(await r.text(),/canary/);empty(f);
    assert.deepEqual(fs.readdirSync(path.join(f.dir,'blobs')),[]);
    db.exec('DROP TRIGGER reject_insert');
  } finally {db.close();}
  assert.equal((await f.upload()).status,201);
});

test('storage symlinks and directories fail closed, and file count includes crash remnants',async t=>{
  const f=await fixture(t,{maxFiles:1});
  const orphan=path.join(f.dir,'tmp','orphan');fs.writeFileSync(orphan,'x');
  assert.equal((await f.upload()).status,507);
  fs.unlinkSync(orphan);fs.symlinkSync(f.config,orphan);
  assert.equal((await f.upload()).status,500);
  fs.unlinkSync(orphan);fs.mkdirSync(orphan);
  assert.equal((await f.upload()).status,500);
  fs.rmdirSync(orphan);assert.equal((await f.upload()).status,201);
});

test('disk inspection and partial-cleanup failures fail closed without losing quota accounting',async t=>{
  const f=await fixture(t,{maxFiles:1});
  const stat=t.mock.method(fs,'statfsSync',()=>{throw new Error('disk inspection failed');});
  assert.equal((await f.upload()).status,500);empty(f);stat.mock.restore();
  const realUnlink=fs.unlink;
  const unlink=t.mock.method(fs,'unlink',(filename,callback)=>filename.startsWith(path.join(f.dir,'tmp'))?
    callback(Object.assign(new Error('cleanup failed'),{code:'EACCES'})):realUnlink(filename,callback));
  const partial=streaming(f);
  await until(()=>fs.readdirSync(path.join(f.dir,'tmp')).length===1);
  partial.destroy();await pause(50);
  unlink.mock.restore();
  assert.equal((await f.upload()).status,507);
  assert.equal(fs.readdirSync(path.join(f.dir,'tmp')).length,1);
});

test('a temporary-file collision is never removed as failed-upload cleanup',async t=>{
  const f=await fixture(t);
  const realCreate=fs.createWriteStream;
  const write=t.mock.method(fs,'createWriteStream',(filename,options)=>{
    fs.writeFileSync(filename,'existing crash artifact');
    return realCreate(filename,options);
  });
  assert.equal((await f.upload()).status,500);write.mock.restore();
  const files=fs.readdirSync(path.join(f.dir,'tmp'));assert.equal(files.length,1);
  assert.equal(fs.readFileSync(path.join(f.dir,'tmp',files[0]),'utf8'),'existing crash artifact');
  assert.equal((await f.upload()).status,201);
});
