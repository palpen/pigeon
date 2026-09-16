import fs from 'node:fs';
import path from 'node:path';
import {randomUUID} from 'node:crypto';
import {Transform, pipeline} from 'node:stream';
import multer from 'multer';

export const MAX_UPLOAD_BYTES = 50 * 1024 * 1024;

// Multer/Busboy reads one extra byte to distinguish an exact-size upload from
// an oversized one. This storage engine never writes that byte to disk.
function limitedStorage(directory, limit) {
  const pending = new WeakMap();
  const ownedPaths = new Set();
  const remove = (filename, callback) => {
    if (!ownedPaths.has(filename)) return callback();
    fs.unlink(filename, err => {
      if (!err || err.code === 'ENOENT') { ownedPaths.delete(filename); callback(); }
      else callback(err);
    });
  };
  return {
    _handleFile(req, file, callback) {
      file.path = path.join(directory, randomUUID());
      let size = 0;
      const bound = new Transform({transform(chunk, encoding, done) {
        if (size + chunk.length > limit) return done(new multer.MulterError('LIMIT_FILE_SIZE'));
        size += chunk.length;
        done(null, chunk);
      }});
      const output = fs.createWriteStream(file.path, {flags:'wx', mode:0o600});
      output.once('open', () => ownedPaths.add(file.path));
      let settle;
      const settled = new Promise(resolve => { settle = resolve; });
      pending.set(file, {output, settled});
      pipeline(file.stream, bound, output, err => {
        const finish = cleanupError => {
          pending.delete(file);
          settle();
          callback(cleanupError || err, err ? undefined : {path:file.path, size});
        };
        if (err) remove(file.path, finish);
        else finish();
      });
    },
    _removeFile(req, file, callback) {
      const write = pending.get(file);
      const cleanup = () => remove(file.path, callback);
      if (write) {
        write.output.destroy(new Error('Upload cancelled.'));
        write.settled.then(cleanup);
      } else cleanup();
    }
  };
}

export function boundedUpload({dataDir, types, maxStorageBytes, maxFiles, uploadsPerMinute, minFreeBytes,
  uploadTimeoutMs = 120_000, now = Date.now}) {
  let active = false;
  let idle = Promise.resolve(), release = () => {};
  let attempts = [];
  const middleware = (req, res, next) => {
    const current = now();
    attempts = attempts.filter(t => t > current - 60_000);
    if (attempts.length >= uploadsPerMinute) {
      res.set('Retry-After', String(Math.max(1, Math.ceil((attempts[0] + 60_000 - current) / 1000))));
      return res.status(429).json({error:'Upload rate limit reached. Retry later.'});
    }
    attempts.push(current);
    if (active) return res.set('Retry-After','1').status(429).json({error:'Another upload is in progress. Retry later.'});
    try {
      let bytes = 0, count = 0;
      for (const dir of ['blobs','tmp']) {
        for (const name of fs.readdirSync(path.join(dataDir,dir))) {
          const stat = fs.lstatSync(path.join(dataDir,dir,name));
          if (!stat.isFile()) throw new Error('Unexpected entry in upload storage.');
          bytes += stat.size; count++;
        }
      }
      const disk = fs.statfsSync(dataDir);
      const available = Math.floor(Math.min(maxStorageBytes - bytes, disk.bavail * disk.bsize - minFreeBytes));
      if (count >= maxFiles || available <= 0) return res.status(507).json({error:'Storage limit reached. Delete files or increase the configured limit.'});
      active = true;
      idle = new Promise(resolve => { release = resolve; });
      const limit = Math.min(MAX_UPLOAD_BYTES, available);
      const timer = setTimeout(() => req.destroy(), uploadTimeoutMs);
      timer.unref();
      const upload = multer({storage:limitedStorage(path.join(dataDir,'tmp'), limit),
        limits:{fileSize:limit,files:1,fields:0,parts:1},fileFilter(req,file,cb) {
          if (!types[path.extname(file.originalname).toLowerCase()]) return cb(Object.assign(new Error('Unsupported file type.'),{status:415}));
          cb(null,true);
        }}).single('file');
      upload(req,res,err => {
        clearTimeout(timer);
        // The commit in the next handler is synchronous. The data-directory
        // lock prevents another process from bypassing this in-process gate.
        active = false;
        release();
        if (err?.code === 'LIMIT_FILE_SIZE' && limit < MAX_UPLOAD_BYTES) {
          err = Object.assign(new Error('Upload exceeds remaining storage capacity.'),{status:507});
        } else if (err && /^(Unexpected end of (form|file)|Multipart:|Malformed part header)/.test(err.message)) {
          err = Object.assign(new Error('Malformed multipart upload.'), {status:400});
        }
        next(err);
      });
    } catch (err) { active = false; release(); next(err); }
  };
  middleware.idle = () => idle;
  return middleware;
}
