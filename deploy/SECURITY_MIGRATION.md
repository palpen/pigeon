# Security-hardening migration and rollback

Code/PR readiness and production deployment are separate. Do not change a running service, Serve route, OS account, credentials, or agent configuration until the owner confirms this migration. Do not enable Funnel or additional owner identities.

## Preflight and approval package

1. Identify the actual LaunchAgent label, loaded program path, working directory, Node version, data directory, and existing HTTPS URL. A renamed repository does not prove the service path changed. Inspect environment **names**, not secret values, when checking for the old `AGENT_TOKEN`.
2. Read `tailscale version`, `tailscale serve --help`, and `tailscale serve status --json`. Confirm Unix proxy support. Retain the existing port/URL and unrelated Serve handlers.
3. Record the current code revision, Node executable, LaunchAgent file, and Serve target privately. Inventory intended agents and scopes; prefer upload-only. Keep private deployment details and credentials out of the PR.
4. Confirm data and socket directories are owned by the service user with mode 0700, and Tailscale's service identity can connect without broadening permissions. Registry/client files use mode 0600 in private directories outside the repository. The new Unix socket path must fit the 103-byte macOS limit. The data filesystem must be local.
5. Run `npm ci` and `npm test` in a separate development checkout with disposable data. Review [README](../README.md) for trust limits, credential lifecycle, limits, and crash recovery.
6. Present the identified paths, backup destination, quota settings, agent changes, commands, rollback plan, and brief service interruption to the owner for confirmation. Do not treat approval to create a PR as deployment approval.

## After confirmation

1. Stop the actual service and wait for the process to exit. Make a consistent private backup of the entire data directory and record the old code/LaunchAgent/Serve configuration. Preserve original uploads.
2. Install the reviewed code and its lockfile, retaining the existing data path, URL, and database. Use Node 24+. Adjust only the reviewed directory permissions. Install the revised LaunchAgent configuration, including absolute `DATA_DIR`, `AGENT_TOKENS_FILE`, and explicit limits. Remove `AGENT_TOKEN` entirely.
3. Create only the approved agent credentials outside the repository; configure each intended uploader's `PIGEON_TOKEN_FILE` privately. Tokens are limited only when used: a device that still presents owner identity without Authorization has owner access.
4. Start Pigeon. Verify the process owns the data lock, the Unix socket is mode 0600 inside mode 0700, and direct loopback requests without tokens return 403. Anonymous local access must not be restored.
5. Replace only the Pigeon Serve target with `unix:/actual/private/data/run/pigeon.sock`, keeping its existing HTTPS port and URL. Example only:

   ```sh
   /Applications/Tailscale.app/Contents/MacOS/Tailscale serve --bg --https=8443 unix:/actual/private/data/run/pigeon.sock
   ```

6. Through real Tailscale, verify the owner browser can list, upload, preview, download, and delete a disposable file. Verify wrong owner identity is denied; verify an upload-only agent can upload and return a link but cannot GET/HEAD/download/delete it, even when owner headers accompany the token. Check invalid/revoked/expired tokens cannot fall back to owner access.
7. Verify the actual automatic report uploader, then restart the service and repeat owner read plus agent upload. Confirm existing uploads remain available. Save dated results; retain the backup until deployment is verified.

If the Tailscale process cannot connect to the private socket, stop and investigate its service identity. Do not relax the socket directory or restore TCP identity-header trust as a workaround.

## Rollback

Stop the new service and wait for shutdown. Restore the prior application revision, dependency lockfile/install, LaunchAgent/environment, and old Serve target **together**. Keep the data directory and uploads; this change does not migrate the `files` schema. Restore the backup only for a separately diagnosed data-recovery need, with the owner's approval. Recheck owner browser access and the previous agent workflow.

Rollback to the original code re-enables its anonymous-localhost/header-trust weaknesses and removes scoped tokens/quotas. Record that explicitly. Do not restore only the TCP route while leaving new code active: the hardened TCP listener intentionally rejects anonymous owner-header requests.

## Validation status on 2026-09-16

- Mac mini development: Node v25.6.0, all 41 isolated regression tests passed. Tests cover Unix owner access, TCP denial, token lifecycle, storage limits/failure cleanup, concurrent process startup, SIGTERM/restart and SIGKILL stale-socket recovery.
- Preflight found a renamed service checkout with an obsolete path in the saved/loaded LaunchAgent. Correct the reviewed program, working-directory, and log paths during the approved migration before any restart; a code-only update is insufficient.
- `npm audit --omit=dev`: zero known vulnerabilities in the locked dependencies. LaunchAgent plist, upload-shell syntax, JavaScript syntax, and Git whitespace checks passed.
- Installed Tailscale 1.102.3 documents `unix:` Serve targets in its own help. The existing production route still targets the original loopback service.
- Live route migration, Tailscale service access to the new private socket, real owner browser flows, and the production report agent remain **deployment checks**, not completed validation. No production service/route, credential, or uploaded content was changed for this PR.
