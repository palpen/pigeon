# Pigeon security fixes: Mac mini handoff

## Status and scope

This branch is work in progress. Do not merge or deploy it yet.

The user approved these changes:

- Require authentication for direct local HTTP requests.
- Add upload-storage, file-count, upload-rate, and free-disk limits.
- Give agents separate, revocable tokens with read, upload, and delete scopes.
- Preserve browser access through the owner's Tailscale identity without a new login prompt.

The user approved publishing this branch for continuation on the Mac mini. No live
service, Tailscale route, credentials, or uploaded files have been changed.
Family access is not implemented: browser access remains owner-only. Do not add
family identities or broaden access without a separate request.

## Get the work safely

Use a separate development checkout or worktree. Do not switch the branch in the
live service's checkout. Inspect local changes and any AGENTS.md instructions first.

From an existing clean development clone:

```sh
git fetch origin
git switch --track origin/wip/pigeon-security-hardening
npm ci
npm test
```

If the local branch already exists, switch to it and inspect its state rather than
running the tracking-branch command again. Requires Node 24 or newer. Use a temporary
DATA_DIR for manual tests; never use the production data directory for tests.

## Implemented, but not fully verified

| File | Change |
| --- | --- |
| server.js | Rejects anonymous localhost requests; applies agent scopes; only trusts owner identity headers on Unix-socket requests. |
| security.js | Reads a mode-0600 JSON token registry; validates token hashes/scopes; supports optional expiry; reloads for immediate revocation. |
| uploads.js | Counts blob and temporary files, including orphans; serializes uploads; enforces quota, file count, rate, and disk reserve; adds a 120-second upload timeout. |
| start.js | Starts a token-only loopback API and an OS-protected Unix socket for Tailscale; attempts stale-socket recovery and graceful shutdown. |
| scripts/add-agent.js | Creates a random token in a private file and puts its SHA-256 hash in the server registry. |
| scripts/upload.sh | Reads PIGEON_TOKEN_FILE and sends the token through curl stdin, not command-line arguments. |
| test/security.test.js | Adds eight security tests. |
| test/relay.test.js | Moves the existing owner-flow integration test to a Unix socket. |

### Current settings

| Variable | Default / use |
| --- | --- |
| MAX_TOTAL_STORAGE_BYTES | 5368709120 (5 GiB of blob and temporary-file payloads) |
| MAX_FILES | 10000, including orphan/temporary files |
| UPLOADS_PER_MINUTE | 20 attempts globally; in memory, resets on restart |
| MIN_FREE_DISK_BYTES | 1073741824 (1 GiB reserve checked before upload) |
| AGENT_TOKENS_FILE | Absolute path to a private token registry; no tokens enabled if absent |
| OWNER_LOGIN / PUBLIC_URL / DATA_DIR | Existing settings retained |
| AGENT_TOKEN | Removed; startup fails if this old variable is set |
| PIGEON_TOKEN_FILE | Client-side token file used by the upload script |

There is one active upload at a time. Other uploads receive 429 and Retry-After.
The quota does not include SQLite files, logs, or other applications' disk usage.
The free-space check is not an OS-level reservation. Do not describe it as a hard
guarantee that the whole disk cannot fill.

## Recorded test result

In the original Linux workspace, Node v24.19.0 ran npm test:

- Eight tests in test/security.test.js passed.
- The existing integration test failed before requests could run because Unix
  socket creation was denied: listen EPERM at a temporary test.sock path.
- No Mac, live Tailscale, service-restart, or end-to-end browser test has run.

Do not treat this as a passing full test suite. Do not disable the failed test,
substitute TCP for the trusted socket, or restore header trust on TCP to make it pass.

## Required remaining work, in order

### 1. Review the security boundary

- Confirm Node on macOS exposes remoteAddress and remoteFamily as undefined for
  the actual Unix-socket request, and not for TCP requests. Consider a more explicit
  listener-bound trust marker if that is clearer and safer.
- Confirm the installed Tailscale build can proxy to the Unix socket and supply
  owner identity headers. Confirm the Tailscale process can access the socket with
  its current service identity. Do not relax the socket directory to world access.
- A Unix socket with mode 0600 does NOT isolate software running as the same OS
  user. Such software can reach the socket, forge owner headers, or read files.
  Document this residual risk. Stronger isolation requires a separate service OS
  account and corresponding data/socket permissions; do not change OS accounts
  without user approval.
- Ensure a supplied invalid or restricted token never falls back to full owner
  access, even when correct owner headers arrive through the trusted socket.

### 2. Complete regression tests and fix failures

- Run npm test on the Mac mini in an isolated checkout.
- Test Unix-socket owner access, wrong/missing owner identity, and all CSRF checks.
- Test invalid/revoked/expired tokens on the Unix listener as well as TCP; verify
  upload-only and read-only restrictions including HEAD, raw, download, and delete.
- Test malformed registry entries, duplicate IDs/hashes, unsafe permissions,
  symlinks, missing files, and invalid expiry. Confirm failure is closed and secrets
  never reach error responses or logs.
- Test quota and 50 MiB boundaries (exact limit, just below, just above), malformed
  and chunked multipart bodies, request abort, timeout, and failed disk/DB writes.
  Confirm partial files are removed and the upload slot is released in each case.
- Test persisted quotas after restart, orphan/temporary file accounting, deletion
  freeing capacity, rate-window reset, and concurrent upload rejection.
- Test start.js: graceful shutdown/restart, stale socket after crash, live socket
  refusal, non-socket path refusal, occupied TCP port, invalid configuration, and
  simultaneous startup. In particular, review the stale-socket probe/unlink race:
  concurrent starts must not unlink a newly live socket or permit two writers.
  The in-memory upload lock assumes exactly one process per data directory.
- Add tests for token creation and the upload script, including file paths with
  spaces and quotes. Review registry updates for concurrent-write loss and partial
  failure; never overwrite an existing client token file or print a token.
- If needed, make the local port configurable for isolated startup tests; the
  current start.js hard-codes 8787 and must not be run beside production on that port.

### 3. Finish documentation and safe configuration

- Update README.md: it currently describes unauthenticated localhost, the old
  full-admin AGENT_TOKEN, and the old TCP Serve target. Those instructions are stale.
- Update deploy/com.example.pigeon.plist.example for the new settings, keeping
  real paths, owner identities, and secrets out of version control.
- Add ignore patterns for registry/token files or require them outside the repo.
  The current .gitignore has not been updated for the new credential file types.
- Document token creation, upload, revocation, rotation, optional expiry, and
  recovery from a malformed registry. Prefer upload-only tokens for report agents.
  Automatic renewal is not required. Keep tokens and registries outside the repo
  in private directories; do not put them in prompts or command history.
- Explain 429/507 errors and bounded retry behavior. Do not retry a quota failure
  indefinitely. Preserve original files; do not auto-delete user uploads.
- Explain how orphan/temporary files can be inspected and recovered after a crash;
  do not delete them blindly while the service is running.

Token creation syntax (use real private absolute paths outside the repository):

```sh
node scripts/add-agent.js reports upload /private/path/agents.json /private/path/reports.token
```

The parent directories must exist and be private. The tool writes credentials;
run it only for the requested agent configuration, never as a public example.

### 4. Prepare and validate deployment; do not deploy automatically

- Identify the actual production service, DATA_DIR, Node version, Tailscale build,
  and Serve configuration without printing secrets. Keep the existing URL.
- Present the migration and rollback plan to the user and obtain confirmation
  before changing the running service, route, or agent configuration.
- Arrange a consistent backup of SQLite metadata and blobs before deployment.
- Configure AGENT_TOKENS_FILE; replace/remove AGENT_TOKEN; configure each uploader's
  PIGEON_TOKEN_FILE. An agent token is only limited if the agent actually uses it;
  owner-identity access without a token still has owner permissions.
- The proposed Serve target is unix:/absolute/data/path/run/pigeon.sock instead of
  http://127.0.0.1:8787. Confirm this syntax and permissions against the installed
  Tailscale build before changing the live route. A typical command to validate is:

```sh
/Applications/Tailscale.app/Contents/MacOS/Tailscale serve --bg --https=8443 unix:/absolute/data/path/run/pigeon.sock
```

- Do not run that example against production before approval. The actual DATA_DIR
  and route must be discovered. If Unix proxying is unsupported, report the blocker;
  do not silently fall back to trusting arbitrary loopback headers.
- After approved deployment, test browser list/upload/preview/download/delete
  through Tailscale, automatic report upload, denied token read/delete, anonymous
  localhost denial, and service restart. Use disposable test files only.
- Rollback must restore the previous code, Serve route, and compatible environment
  together. Do not delete production data. Warn that old code restores the original
  weaknesses. Keep the backup until the new version is verified.

## Completion criteria

All tests pass on macOS; startup and real Tailscale/browser/agent flows are verified;
documentation and deployment examples match the code; no secrets are committed;
remaining same-user OS trust and disk-reserve limits are clearly stated. Report
code readiness separately from whether the user approved and completed deployment.
