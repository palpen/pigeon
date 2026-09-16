import express from 'express';
import multer from 'multer';
import { marked } from 'marked';
import sanitizeHtml from 'sanitize-html';
import { DatabaseSync } from 'node:sqlite';
import { randomUUID } from 'node:crypto';
import {authenticateAgent, readAgents, positiveInteger, privateDirectory} from './security.js';
import {boundedUpload} from './uploads.js';
import {lockDataDirectory} from './storage.js';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const types = {'.md':['markdown','text/markdown'],'.markdown':['markdown','text/markdown'],'.txt':['text','text/plain'],'.png':['image','image/png'],'.jpg':['image','image/jpeg'],'.jpeg':['image','image/jpeg'],'.gif':['image','image/gif'],'.webp':['image','image/webp'],'.avif':['image','image/avif'],'.pdf':['pdf','application/pdf']};
export function createApp({dataDir = process.env.DATA_DIR || path.join(ROOT,'data'), owner = process.env.OWNER_LOGIN, publicUrl = process.env.PUBLIC_URL,
  agentTokensFile = process.env.AGENT_TOKENS_FILE,
  maxStorageBytes = process.env.MAX_TOTAL_STORAGE_BYTES ?? 5 * 1024 ** 3,
  maxFiles = process.env.MAX_FILES ?? 10000,
  uploadsPerMinute = process.env.UPLOADS_PER_MINUTE ?? 20,
  minFreeBytes = process.env.MIN_FREE_DISK_BYTES ?? 1024 ** 3,
  uploadTimeoutMs = 120_000, now = Date.now} = {}) {
  if (Object.hasOwn(process.env, 'AGENT_TOKEN')) throw new Error('AGENT_TOKEN is no longer supported. Migrate to AGENT_TOKENS_FILE.');
  readAgents(agentTokensFile);
  if (publicUrl !== undefined) {
    const url = new URL(publicUrl);
    if (url.protocol !== 'https:' || url.username || url.password || url.pathname !== '/' || url.search || url.hash) throw new Error('PUBLIC_URL must be an HTTPS origin.');
    publicUrl = url.origin;
  }
  const publicHost = publicUrl && new URL(publicUrl).host;
  maxStorageBytes = positiveInteger(maxStorageBytes,'MAX_TOTAL_STORAGE_BYTES');
  maxFiles = positiveInteger(maxFiles,'MAX_FILES');
  uploadsPerMinute = positiveInteger(uploadsPerMinute,'UPLOADS_PER_MINUTE');
  minFreeBytes = positiveInteger(minFreeBytes,'MIN_FREE_DISK_BYTES');
  const unlock = lockDataDirectory(dataDir);
  let db;
  try {
    for (const directory of ['blobs', 'tmp']) {
      fs.mkdirSync(path.join(dataDir,directory),{recursive:true,mode:0o700});
      privateDirectory(path.join(dataDir,directory));
    }
    const filename = path.join(dataDir,'relay.sqlite');
    const fd = fs.openSync(filename, fs.constants.O_CREAT | fs.constants.O_RDWR | fs.constants.O_NOFOLLOW, 0o600);
    try {
      if (!fs.fstatSync(fd).isFile()) throw new Error('Unsafe database file.');
      fs.fchmodSync(fd, 0o600);
    } finally { fs.closeSync(fd); }
    db = new DatabaseSync(filename);
    db.exec('PRAGMA journal_mode=WAL; CREATE TABLE IF NOT EXISTS files (id TEXT PRIMARY KEY, name TEXT NOT NULL, kind TEXT NOT NULL, mime TEXT NOT NULL, size INTEGER NOT NULL, created TEXT NOT NULL)');
  } catch (err) { db?.close(); unlock(); throw err; }
  const trustedRequests = new WeakSet();
  const app = express();
  app.disable('x-powered-by');
  app.use((req,res,next)=>{
    res.set({'X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer','Cache-Control':'no-store','Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"});
    const port = req.socket.localPort ?? 8787;
    const localHosts = [`localhost:${port}`,`127.0.0.1:${port}`];
    const host = req.get('host');
    if (!localHosts.includes(host) && host !== publicHost) return res.status(403).json({error:'Unrecognized host.'});
    const supplied = req.get('authorization');
    if (req.rawHeaders.filter((h,i) => i % 2 === 0 && h.toLowerCase() === 'authorization').length > 1) return res.status(403).json({error:'Supply only one Authorization header.'});
    let agent;
    try { agent = supplied === undefined ? undefined : authenticateAgent(supplied,readAgents(agentTokensFile)); }
    catch { return res.status(503).json({error:'Agent authentication configuration is unavailable.'}); }
    // A TCP caller can forge every HTTP header. Trust Tailscale identity only
    // through the private Unix socket, never through the loopback TCP listener.
    const trustedProxy = trustedRequests.has(req);
    const isOwner = supplied === undefined && trustedProxy && owner && req.get('tailscale-user-login') === owner;
    if (!agent && !isOwner) return res.status(403).json({error:'Use the approved Tailscale account or a valid agent token.'});
    if (agent) {
      const scope = ['GET','HEAD'].includes(req.method) ? 'read' :
        req.method === 'POST' && /^\/api\/files\/?$/i.test(req.path) ? 'upload' :
        req.method === 'DELETE' && /^\/api\/files\/[^/]+\/?$/i.test(req.path) ? 'delete' : null;
      if (!scope || !agent.scopes.includes(scope)) return res.status(403).json({error:'Agent token does not permit this operation.'});
    }
    if (!['GET','HEAD','OPTIONS'].includes(req.method)) {
      const origin = req.get('origin');
      if (origin && origin !== publicUrl && !(localHosts.includes(host) && origin === `http://${host}`)) return res.status(403).json({error:'Cross-origin request blocked.'});
      if (!agent && req.get('x-pigeon-request') !== '1' && req.get('x-relay-request') !== '1') return res.status(403).json({error:'Include X-Pigeon-Request: 1.'});
    }
    next();
  });
  const upload = boundedUpload({dataDir,types,maxStorageBytes,maxFiles,uploadsPerMinute,minFreeBytes,uploadTimeoutMs,now});
  const shape = row => ({...row,url:`/files/${row.id}`,downloadUrl:`/api/files/${row.id}/download`});
  const lookup = (req,res,next) => {req.fileRecord=db.prepare('SELECT * FROM files WHERE id=?').get(req.params.id); if(!req.fileRecord)return res.status(404).json({error:'File not found.'}); next();};
  app.get('/api/files',(req,res)=>res.json({files:db.prepare('SELECT * FROM files ORDER BY created DESC').all().map(shape)}));
  app.post('/api/files',upload,(req,res,next)=>{
    if(!req.file)return res.status(400).json({error:'Upload one file using the file field.'});
    const id=randomUUID(), blob=path.join(dataDir,'blobs',id);
    try {
      const name=Buffer.from(req.file.originalname,'latin1').toString('utf8').replace(/[\x00-\x1f\x7f]/g,'').slice(0,240) || 'Untitled';
      const [kind,mime]=types[path.extname(req.file.originalname).toLowerCase()];
      const row={id,name,kind,mime,size:req.file.size,created:new Date().toISOString()};
      fs.renameSync(req.file.path,blob); fs.chmodSync(blob,0o600);
      db.prepare('INSERT INTO files VALUES (?,?,?,?,?,?)').run(id,name,kind,mime,row.size,row.created);
      res.status(201).json({...shape(row),url:publicUrl ? `${publicUrl}/files/${id}` : `/files/${id}`});
    } catch(err) {
      // Best-effort cleanup; any undeletable orphan still counts against quota.
      for (const filename of [req.file.path, blob]) {
        try { fs.rmSync(filename,{force:true}); } catch { /* Retain for operator recovery. */ }
      }
      next(err);
    }
  });
  app.get('/api/files/:id',lookup,(req,res)=>res.json(shape(req.fileRecord)));
  app.get('/api/files/:id/content',lookup,(req,res)=>{
    const f=req.fileRecord;
    if(!['markdown','text'].includes(f.kind))return res.status(415).json({error:'This file has no text preview.'});
    if(f.size>5*1024*1024)return res.status(413).json({error:'Text previews are limited to 5 MB. Download this file to read it.'});
    const source=fs.readFileSync(path.join(dataDir,'blobs',f.id),'utf8');
    const html=f.kind==='markdown' ? sanitizeHtml(marked.parse(source),{allowedTags:sanitizeHtml.defaults.allowedTags.concat(['img','del','input']),allowedAttributes:{...sanitizeHtml.defaults.allowedAttributes,img:['src','alt','title'],input:['type','checked','disabled'],a:['href','title','target','rel']},allowedSchemes:['http','https'],transformTags:{a:sanitizeHtml.simpleTransform('a',{target:'_blank',rel:'noopener noreferrer'}),input:(tag,attrs)=>({tagName:'input',attribs:{type:'checkbox',disabled:'',...(Object.hasOwn(attrs,'checked')?{checked:''}:{})}})}}) : null;
    res.json({source,html});
  });
  app.get('/api/files/:id/raw',lookup,(req,res)=>{
    const f=req.fileRecord;
    res.set('Content-Security-Policy',"sandbox; default-src 'none'");
    res.type(f.mime).sendFile(path.resolve(dataDir,'blobs',f.id));
  });
  app.get('/api/files/:id/download',lookup,(req,res)=>res.download(path.resolve(dataDir,'blobs',req.fileRecord.id),req.fileRecord.name));
  app.delete('/api/files/:id',lookup,(req,res)=>{
    // Unlink before metadata removal: a disk error leaves the item recoverable/retryable.
    fs.rmSync(path.join(dataDir,'blobs',req.fileRecord.id),{force:true});
    db.prepare('DELETE FROM files WHERE id=?').run(req.fileRecord.id);res.status(204).end();
  });
  app.use(express.static(path.join(ROOT,'public'),{index:false}));
  app.get(['/', '/files/:id'],(req,res)=>res.sendFile(path.join(ROOT,'public','index.html')));
  app.use((err,req,res,next)=>{
    if (res.headersSent) return next(err);
    const status = err.code === 'LIMIT_FILE_SIZE' ? 413 : err.code === 'ENOSPC' ? 507 :
      err.status || (err instanceof multer.MulterError ? 400 : 500);
    const message = status === 413 ? 'Files must be 50 MiB or smaller.' : status === 507 ? 'Upload exceeds available storage capacity.' :
      err.status || err instanceof multer.MulterError ? err.message : 'Could not complete the request.';
    // Do not log arbitrary parser, filesystem, or database error messages.
    if (status === 500 && !req.destroyed) console.error('Pigeon request failed (internal storage error).');
    if (!res.destroyed) res.status(status).json({error:message});
  });
  let closing;
  return {
    app,
    proxyHandler(req,res) {
      // Only start.js attaches this handler, and only to the private Unix
      // listener. Even accidental attachment to TCP must not trust headers.
      if (req.socket.remoteAddress === undefined && req.socket.remoteFamily === undefined) trustedRequests.add(req);
      app(req,res);
    },
    close() {
      return closing ??= upload.idle().then(() => { try { db.close(); } finally { unlock(); } });
    }
  };
}
if(process.argv[1] && path.resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
  // Finish evaluating this module before start.js imports createApp from it.
  // Awaiting the import at module scope would deadlock the entry point.
  import('./start.js').then(({start}) => start()).then(instance => {
    console.log(`Pigeon: local token API on 127.0.0.1:${instance.local.address().port}; private Tailscale socket ready.`);
  }).catch(() => {
    console.error('Pigeon could not start. Check configuration, private paths, listener availability, and the data-directory lock.');
    process.exitCode = 1;
  });
}
