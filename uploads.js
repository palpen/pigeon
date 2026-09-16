import fs from 'node:fs';
import path from 'node:path';
import multer from 'multer';

export const MAX_UPLOAD_BYTES = 50 * 1024 * 1024;

export function boundedUpload({dataDir, types, maxStorageBytes, maxFiles, uploadsPerMinute, minFreeBytes}) {
  let active = false;
  // Global rate limit: changing tokens or forwarding headers cannot bypass it.
  let attempts = [];
  return (req, res, next) => {
    const now = Date.now();
    attempts = attempts.filter(t => t > now - 60_000);
    if (attempts.length >= uploadsPerMinute) {
      res.set('Retry-After', String(Math.max(1, Math.ceil((attempts[0] + 60_000 - now) / 1000))));
      return res.status(429).json({error:'Upload rate limit reached. Retry later.'});
    }
    attempts.push(now);
    if (active) return res.set('Retry-After','1').status(429).json({error:'Another upload is in progress. Retry later.'});
    try {
      // Include orphan blobs and partial uploads left by a crash, not just DB rows.
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
      // Serialize writes and cap the temporary file too; checking only after an
      // upload completes allows concurrent or incomplete uploads to fill the disk.
      const limit = Math.min(MAX_UPLOAD_BYTES, available);
      const timer = setTimeout(() => req.destroy(), 120_000);
      timer.unref();
      const upload = multer({dest:path.join(dataDir,'tmp'),limits:{fileSize:limit,files:1,fields:0,parts:1},fileFilter(req,file,cb) {
        if (!types[path.extname(file.originalname).toLowerCase()]) return cb(Object.assign(new Error('Unsupported file type.'),{status:415}));
        cb(null,true);
      }}).single('file');
      upload(req,res,err => {
        clearTimeout(timer);
        // All following commit operations are synchronous. Release only after
        // Multer has completed its writes and error/abort cleanup.
        active = false;
        if (err?.code === 'LIMIT_FILE_SIZE' && limit < MAX_UPLOAD_BYTES) {
          err = Object.assign(new Error('Upload exceeds remaining storage capacity.'),{status:507});
        }
        next(err);
      });
    } catch (err) { active = false; next(err); }
  };
}
