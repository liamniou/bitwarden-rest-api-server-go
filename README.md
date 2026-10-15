# Bitwarden REST API Server (Go)

A lightweight Go reimplementation of `bw serve`, the Bitwarden CLI
[Vault Management API](https://bitwarden.com/help/vault-management-api/). It's a
drop-in replacement for
[`ghcr.io/kimdre/bitwarden-rest-api-server`](https://github.com/kimdre/bitwarden-rest-api-server):
same port, same environment variables, same endpoints, and the same JSON
responses.

## Why

The original image wraps the official Node.js Bitwarden CLI (a ~140 MB
`pkg`-bundled binary). Reverse engineering the shipped CLI 2026.9.1 showed
where its idle CPU goes:

| Source | What happens |
| --- | --- |
| Sync loop (`entrypoint.sh`) | Every `VAULT_SYNC_INTERVAL` seconds, a new `bw sync --force` process cold-starts Node, loads the WASM SDK, and downloads and re-writes the whole vault, whether or not anything changed. |
| Docker healthcheck (every 10 s) | `GET /status` runs `unlockWithAutoUnlockKey`, which re-initializes the SDK's user crypto and writes state back to disk on every call. |
| Storage layer | `LowdbStorageService` runs with `allowCache=false` and `requireLock=true`, so each state read takes a file lock and re-parses the full `data.json` (the entire encrypted vault), and each write re-serializes it. |

This server logs in once, keeps the decrypted vault in memory, answers reads
without any crypto or disk I/O, and syncs by first asking the server for the
account revision date. The full vault is downloaded only when something
changed.

Measured side by side on a local Vaultwarden with a 1,013-item vault. Both
containers ran with their built-in healthcheck (every 10 s) and sync loop,
and CPU was read from cgroup accounting:

| | `bw serve` (Node) | this server (Go) |
| --- | --- | --- |
| Image size | 240 MB | 20 MB |
| Time to unlocked vault | 12.1 s | 0.26 s |
| CPU used during startup | 5.9 s | 0.10 s |
| Idle CPU (5 min average) | 2.19% of a core | 0.20% of a core |
| Memory (idle) | 169 MiB | 15 MiB |
| CPU for 500 item reads + 50 full lists | 2.27 s | 0.55 s |
| Median request latency | 2.9 ms | 0.85 ms |

With an 11-item vault the idle gap was 1.08% vs 0.23%. The Node figures grow
with vault size; this server's idle cost doesn't. Most of the Go container's
remaining idle CPU is Docker starting the `healthcheck` process every 10 s.

### Benefits

* About 11x less idle CPU, and the gap grows with vault size.
* About 10x less memory (15 MiB vs 169 MiB) and a 20 MB image instead of 240 MB.
* Ready in a quarter of a second instead of 12 seconds, so restarts and
  healthchecks recover almost immediately.
* No disk writes during normal operation. Vault secrets live only in
  memory and are dropped on `POST /lock` or shutdown.
* A single static binary on `distroless/static` with no shell, Node.js or
  libc, which shrinks the attack surface.
* Same API, same environment variables and same JSON output, so switching
  is a one-line image change.

## How it was created

1. **Reverse engineering the original image.** The image's filesystem was
   exported and the `bw` binary was identified as a `yao-pkg` bundle of the
   Node.js CLI. Its embedded virtual filesystem was unpacked to get `bw.js`
   and its source map. The source map contained all 1,167 original
   TypeScript files of CLI 2026.9.1. These were analyzed with
   [REA](https://www.npmjs.com/package/rea-agents) (static analysis only)
   to locate the `bw serve` routes, the command implementations, the
   storage layer and the crypto paths, and to find the CPU hot spots
   listed above.
2. **Reimplementation from the observed behavior.** Each route's handling
   (option parsing, validation messages, permission and policy checks,
   search, and response shapes) was ported to Go. The Bitwarden client
   cryptography (PBKDF2/Argon2id, HKDF key stretching, AES-CBC-HMAC
   EncStrings, RSA-OAEP key wrapping, per-item cipher keys, encrypted
   attachments and Sends) was implemented on the Go standard library and
   `golang.org/x/crypto`.
3. **Differential testing against the original.** The original image and
   this server were run side by side against the same Vaultwarden account,
   and 143 requests (reads, writes and error cases) were diffed, including
   JSON key order. All differences were fixed except three that are bugs in
   the original. Data written by this server was read back by the official
   CLI to confirm compatibility.
4. **Regression tests and benchmarks.** The captured reference output is
   checked in as a golden test. Crypto is tested against independently
   computed vectors, TOTP against RFC 6238, and concurrency with the race
   detector. CPU and memory were measured with both containers running
   their normal healthcheck and sync loops.

## Getting started

1. [Get your personal API key](https://bitwarden.com/help/personal-api-key/)
   (`client_id` / `client_secret`).
2. Create a `.env` file next to `docker-compose.yml`:

   ```env
   # https://vault.bitwarden.eu for EU users, or your own instance URL
   BW_HOST=https://vault.bitwarden.com
   BW_CLIENTID=<your_client_id>
   BW_CLIENTSECRET=<your_client_secret>
   BW_PASSWORD=<your_master_password>
   ```

3. Run `docker compose up -d`.

```sh
curl http://localhost:8087/status
curl http://localhost:8087/object/password/github
```

### Configuration

| Variable | Default | Description |
| --- | --- | --- |
| `BW_HOST` | `https://vault.bitwarden.com` | Server base URL. `/api` and `/identity` are derived from it, as with `bw config server`. |
| `BW_CLIENTID`, `BW_CLIENTSECRET` | | Personal API key (recommended). |
| `BW_USER` | | Email for password login, used when no API key is set. Two-step login needs `BW_TWO_FACTOR_TOKEN` and `BW_TWO_FACTOR_METHOD`. |
| `BW_PASSWORD` | | Master password used to unlock the vault at startup. If unset, the vault stays locked until `POST /unlock`. |
| `VAULT_SYNC_INTERVAL` | `120` | Background sync interval in seconds. `0` disables it. |
| `VAULT_SYNC_FORCE` | `false` | Always download the full vault instead of checking the revision date first. |
| `BITWARDENCLI_APPDATA_DIR` | `/data` | Stores the device identifier, so restarts don't register new devices. An existing CLI `data.json` appId is reused. |
| `BW_SERVE_HOSTNAME` / `--hostname` | `all` | Bind address. Any value other than `all` also enables the CLI's Host-header allow-list. |
| `BW_SERVE_PORT` / `--port` | `8087` | Listen port. |
| `BW_DISABLE_ORIGIN_PROTECTION` / `--disable-origin-protection` | `false` | Accept requests that carry an `Origin` header. |
| `BW_API_URL`, `BW_IDENTITY_URL` | | Override the derived service URLs. |
| `LOG_LEVEL` | `info` | `debug`, `info`, `warn`, or `error`. |

The image's `HEALTHCHECK` runs `bw-serve healthcheck`, which succeeds only when
`/status` reports an unlocked vault.

To persist the device identifier across container re-creation, use the
named-volume overlay:

```sh
docker compose -f docker-compose.yml -f persistent-data.compose.yml up -d
```

## API

All `bw serve` routes are implemented, with the same request handling, errors,
and response envelope (`{"success": ..., "message": ..., "data": ...}`):

| Method | Route |
| --- | --- |
| GET | `/status`, `/generate`, `/list/object/{items,folders,collections,organizations,org-collections,org-members,send}`, `/send/list`, `/object/{item,username,password,uri,totp,notes,exposed,attachment,folder,collection,org-collection,organization,template,fingerprint,send}/{id}` |
| POST | `/sync`, `/lock`, `/unlock`, `/object/{item,folder,org-collection,send}`, `/attachment`, `/move/{id}/{organizationId}`, `/restore/item/{id}`, `/archive/item/{id}`, `/confirm/org-member/{id}`, `/send/{id}/remove-password` |
| PUT | `/object/{item,item-collections,folder,org-collection,send}/{id}` |
| DELETE | `/object/{item,attachment,folder,org-collection,send}/{id}` |
| GET/POST | `/device-approval/{organizationId}[/approve-all, /approve/{id}, /deny-all, /deny/{id}]` |

Query options (`search`, `folderid`, `collectionid`, `organizationid`, `url`,
`trash`, `archived`, `itemid`, `permanent`, `force`, generator flags, and so on)
behave like the CLI's.

## Compatibility notes

* Supported accounts: master-password accounts using PBKDF2 or Argon2id with
  AES-CBC-HMAC user keys, including per-item cipher keys, organizations, and
  provider organizations.
* Not supported: SSO with trusted devices, Key Connector, and accounts already
  migrated to the new COSE/XChaCha20 ("v2") encryption. Login fails with a
  clear error for these.
* Creating file Sends isn't available through `bw serve` either. Text Sends
  are supported.
* Attachment uploads to Azure are limited to 256 MiB (single block blob).
* Client "item viewed" events aren't sent to the events server.
* `POST /unlock` returns a random session key for compatibility, but the
  session is held in memory and there's nothing to export.

## Testing

```sh
go test ./...
```

`internal/server/testdata` holds an encrypted `/api/sync` snapshot from a
throwaway Vaultwarden account, plus the responses the official CLI 2026.9.1
`bw serve` returned for that same vault. `TestParityWithOfficialCLI` requires
byte-for-byte equal output, including key order.

During development, every endpoint was also diffed live against the official
image. Data written by this server (all item types, org items, moved items
with fresh per-item keys, attachments, Sends, org-collection changes, and
member confirmation) was read back by the official CLI with identical results.

## License

GPL-3.0, like the Bitwarden CLI and the original wrapper. The EFF large
wordlist (CC BY 3.0 US) is embedded for passphrases and fingerprint phrases.
