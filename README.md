# Pigeon

A private file shelf for your devices and agents. Upload Markdown, plain text, images (PNG/JPEG/GIF/WebP/AVIF), and PDFs; read previews, search/filter, copy links, download, and delete. Create Markdown notes in the browser. The homepage refreshes every 15 seconds.

## Access and trust

Browser access is owner-only through Tailscale Serve, with no extra login prompt. Configure `OWNER_LOGIN` to the exact Tailscale user login and `PUBLIC_URL` to the existing HTTPS origin (for example, `https://your-host.your-tailnet.ts.net:8443`). No family access or public sharing is enabled.

Pigeon has two listeners:

- **Private Unix socket:** `DATA_DIR/run/pigeon.sock`, mode 0600 in a mode-0700 directory. Only this listener accepts the owner's `Tailscale-User-Login` header. Tailscale Serve must proxy to this socket.
- **Loopback TCP:** `127.0.0.1:8787` by default. Every request requires a scoped agent token. Forged Tailscale identity or forwarding headers never grant access here. Anonymous local browser access is intentionally unavailable.

The socket and file permissions protect against other OS users. They do **not** isolate software running as the service user, which can forge owner headers on the socket or read credentials/data. Stronger isolation requires a separate service OS account and appropriate Tailscale access; this release does not change OS accounts. Keep private directories under trusted parents, and use a local filesystem, not a network or cloud-synced data directory.

A supplied Authorization header always takes precedence over owner identity: an invalid, expired, revoked, or restricted token cannot fall back to owner permissions. An owner-identity device that omits its token still has full owner access. Use a tagged/non-owner agent identity and separate OS user when the agent must not be able to bypass its scope. Tokens still require network access to Pigeon; they do not grant tailnet access.

## Run and configure

Requires Node 24+ on macOS or Linux (built-in SQLite and Unix sockets).

```sh
npm ci
OWNER_LOGIN='you@example.com' \
PUBLIC_URL='https://your-host.your-tailnet.ts.net:8443' \
DATA_DIR='/absolute/private/pigeon-data' \
AGENT_TOKENS_FILE='/absolute/private/pigeon-credentials/agents.json' \
npm start
```

Create the registry with the agent tool below before setting `AGENT_TOKENS_FILE`, or omit that variable to disable token access. An existing empty registry is `[]` with mode 0600. The old `AGENT_TOKEN` variable is unsupported and must be removed, even if empty. A configured missing/invalid registry fails startup; if it becomes invalid later, token requests receive 503 until repaired. Owner access without Authorization remains available through the Unix listener.

| Variable | Default / requirement |
| --- | --- |
| `OWNER_LOGIN` | Exact owner identity; absent means owner access is disabled |
| `PUBLIC_URL` | HTTPS origin, without credentials, query, fragment, or path |
| `DATA_DIR` | `data/` beside `server.js`; service-owned mode 0700 |
| `PORT` | `8787`; `0` selects an ephemeral port for tests |
| `AGENT_TOKENS_FILE` | Optional absolute path to a service-owned mode-0600 JSON file in a private directory |
| `MAX_TOTAL_STORAGE_BYTES` | `5368709120` (5 GiB of blobs and temporary payloads) |
| `MAX_FILES` | `10000`, including orphan and temporary files |
| `UPLOADS_PER_MINUTE` | `20` authenticated upload attempts globally |
| `MIN_FREE_DISK_BYTES` | `1073741824` (1 GiB free-space reserve checked before an upload) |

Storage/rate limits must be positive integers. Data, `blobs/`, `tmp/`, and `run/` directories must be private, owned by the service user, and not symlinks. New directories are created with mode 0700; unsafe existing directories are rejected. Keep the absolute socket path at most 103 UTF-8 bytes for macOS compatibility.

One process may own a data directory. An OS-backed SQLite lock serializes startup, socket recovery, and uploads across processes; SIGKILL releases that lock. Never delete or replace `.pigeon-lock.sqlite` while any instance is running. Graceful SIGTERM/SIGINT shutdown allows five seconds for connections, then aborts them and waits for upload cleanup before releasing the lock. Stale sockets are removed only under the lock after refusing live sockets and non-socket paths.

Use [the LaunchAgent example](deploy/com.example.pigeon.plist.example) with your actual Node executable, paths, owner, and existing URL. Create the data/log directories and token registry before loading it. Keep the host awake, online, signed in, and connected to Tailscale. **Existing installations must follow [the migration plan](deploy/SECURITY_MIGRATION.md) before switching code or routes.**

The new Serve target is a Unix socket:

```sh
/Applications/Tailscale.app/Contents/MacOS/Tailscale serve --bg --https=8443 unix:/absolute/private/pigeon-data/run/pigeon.sock
```

This changes a live route. Confirm deployment first, retain the existing URL, and verify the installed Tailscale process can reach the private socket. Do not make its directory world-accessible or fall back to trusting headers on TCP. See the [Tailscale Serve CLI documentation](https://tailscale.com/docs/reference/tailscale-cli/serve).

## Agent credentials

Keep registries and token files **outside the repository** in existing mode-0700 directories. Run the following only when configuring an intended agent; no real token belongs in a prompt, log, shell history, or Git.

```sh
node scripts/add-agent.js reports upload \
  /absolute/private/pigeon-credentials/agents.json \
  /absolute/private/pigeon-credentials/reports.token
```

The tool writes a random 256-bit token to a new mode-0600 client file and stores only its SHA-256 hash in the registry. It never prints the token or overwrites a client file. Optional expiry is a final UTC argument such as `2027-01-01T00:00:00Z`. Registry entries need unique IDs and hashes, at least one distinct scope, and a valid UTC expiry if present; at most 100 entries are allowed.

| Scope | Allowed operations |
| --- | --- |
| `upload` | `POST /api/files` only; response includes the new file's link |
| `read` | GET/HEAD, including list, metadata, text preview, raw, download, and the UI |
| `delete` | `DELETE /api/files/{id}` |

Scopes can be combined, for example `upload,read`. Prefer `upload` for report agents. Transfer each client token privately to its intended agent device. The registry stays on the server.

From a checkout containing the upload helper:

```sh
PIGEON_URL='https://your-host.your-tailnet.ts.net:8443' \
PIGEON_TOKEN_FILE='/absolute/private/reports.token' \
./scripts/upload.sh '/absolute/path/to/report.md'
```

The script sends Authorization to curl over stdin, not in its argument list; it disables automatic `.curlrc` loading and bounds connection/request time. It prints the upload JSON including the absolute `url`: give that link to the user. An upload-only agent cannot open it, but the owner can. `PIGEON_URL` defaults to the local token API, with `RELAY_URL` as a compatibility fallback. Without a token, the helper only works via the owner's Tailscale identity and has full owner permissions.

To **revoke**, remove the corresponding entry and atomically replace the registry with a validated mode-0600 file. Revocation/expiry applies on the next request; it does not cancel operations already authenticated. To **rotate**, create a new ID and client file, switch the agent to it, verify an upload, then remove the old entry. No restart or automatic renewal is needed.

Registry updates must be serialized with other administrators/tools. The creation tool uses an exclusive `agents.json.lock` directory and atomic rename to avoid lost or partial updates. A competing writer fails without changing credentials and can retry after the first finishes. After a tool crash, confirm no writer remains, inspect the registry and newly created token/temporary files privately, and remove only that abandoned registry lock. A token created before the registry commit may be unusable; preserve it for inspection and use a new filename for a retry. Never overwrite a previously issued token. Repair a malformed registry from a known-good copy or a validated `[]`; preserve mode 0600 and use atomic replacement. Do not print malformed JSON, which may contain secrets.

## API and limits

- `GET /api/files` returns `{ "files": [...] }` with relative viewer/download URLs.
- `GET /api/files/{id}` returns metadata.
- `GET /api/files/{id}/content` returns sanitized HTML and original text for text/Markdown.
- `GET /api/files/{id}/raw` previews the original under a sandbox CSP.
- `GET /api/files/{id}/download` downloads the original.
- `POST /api/files` accepts multipart field `file`, one file and no extra fields.
- `DELETE /api/files/{id}` permanently deletes an item.

Owner mutations require `X-Pigeon-Request: 1` (legacy `X-Relay-Request: 1` also works). All mutations reject a supplied unrecognized Origin, including token requests. Valid bearer tokens do not require the request marker.

Maximum upload is exactly **50 MiB (52,428,800 bytes)**. Text previews are capped at 5 MiB. Duplicate names create separate entries. There is one active upload at a time; its temporary payload is bounded too. Uploads have a 120-second deadline, after which the connection is closed and partial files are cleaned.

- **400/413/415:** malformed request, oversized file, or unsupported extension. Correct the request before retrying.
- **403:** denied identity, token, scope, host, or Origin. Correct credentials/configuration.
- **429:** rate limit or active upload. Honor `Retry-After`; retry at most three times with a small random delay. Reads and deletion remain available.
- **507:** quota, file-count limit, disk reserve, or a full disk. Stop retries and ask the owner to free space or adjust limits.
- **503:** token registry unavailable/invalid. Repair it before retrying.

The rate window is global across tokens and resets on restart. Payload quota includes orphan blobs and crash remnants in `tmp/`, and persists across restarts. SQLite files, logs, and other applications are outside the payload quota. The free-space check is **not an OS reservation**: other processes can consume the reserve. Pigeon never automatically deletes uploaded files to create space. A network failure after commit can leave a successful upload with no response; reconcile the library before retrying to avoid duplicates.

## Recovery, backup, and previews

Stop the service and wait for it to exit before copying the entire data directory. Back up SQLite metadata and blobs together, and keep credential backups separately protected. Git is not a content backup.

After a crash, inspect `tmp/` and compare `blobs/` filenames with `SELECT id, name, size FROM files` in `relay.sqlite` while the service is stopped. Unmatched files count against quota. Preserve a backup, inspect contents privately, and recover a useful orphan by copying it outside storage with the correct extension and re-uploading it. Quarantine or remove only specifically reviewed remnants; never blindly clear `tmp/`, `blobs/`, or lock files while running. A cleanup failure intentionally leaves an accounted-for orphan for operator recovery.

Markdown HTML is sanitized and served under a restrictive CSP. Remote embedded images are blocked; uploaded images can be embedded using `/api/files/{id}/raw`. Relative image bundles are not uploaded automatically. HTML/SVG and arbitrary extensions are rejected. PDF preview depends on browser support; Download remains available. Export HEIC to JPEG/PNG first. Names/extensions determine preview type: this is private storage, not a malware scanner. No third-party fonts, analytics, or CDN assets are used.

## Development and compatibility

```sh
npm ci
npm test
```

Tests use private disposable data directories, ephemeral TCP ports, and Unix sockets; the environment must permit local listeners. They never require or alter a production Tailscale route. macOS tests use `/private/tmp` for short socket paths. Test coverage includes auth/scopes, multipart boundaries and cleanup, storage failures, concurrent starts, crash recovery, and credential tooling.

Pigeon was originally called Relay. Existing installations may keep the original directory, service label, database filename (`relay.sqlite`), and HTTPS URL. Keep production on its deployed revision while developing in a separate checkout/worktree. Source, tests, the lockfile, and documentation belong in Git; uploaded files, databases, logs, dependencies, and credentials do not.
