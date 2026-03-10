# sarek — Post-Quantum Secrets Vault Server

`sarek` is the server binary for the SAREK secrets vault. It exposes a secure REST API for managing cryptographic key materials and encrypted secrets.

---

## Table of Contents

1. [Configuration](#configuration)
2. [First-Run Bootstrap](#first-run-bootstrap)
3. [TLS Setup](#tls-setup)
4. [Running the Server](#running-the-server)
5. [Logging](#logging)
6. [Authentication](#authentication)
7. [Token Revocation](#token-revocation)
8. [API Reference](#api-reference)
9. [YAML Secret Extraction](#yaml-secret-extraction)
10. [curl Examples](#curl-examples)

---

## Setup Steps Prior to First Invocation

## Configuration File

`sarek` reads `/etc/sarek.yml` by default. Use `--config <path>` to override.

```yaml
defaults:
  cache-ttl: 300                  # object cache TTL in seconds
  max-data-node-sz: 1mb           # max size for a single secret (b/kb/mb/gb)
db:
  path: /var/lib/sarek            # directory for BDB environment files
http:
  port: 8443                      # port to listen on
user:
  adminuser: admin                # username created during bootstrap, change to suit
```

All five fields are required; the server will refuse to start if any is missing.

---

## TLS Setup

### Self-Signed Certificate (Development / LAN)

Generate a P-256 ECDSA certificate valid for one year:

```bash
openssl req -x509 \
  -newkey ec \
  -pkeyopt ec_paramgen_curve:P-256 \
  -keyout /etc/sarek/key.pem \
  -out /etc/sarek/cert.pem \
  -sha256 \
  -days 365 \
  -nodes \
  -subj "/CN=sarek"
```

For a LAN server with a known hostname or IP, add a Subject Alternative Name so clients accept it without extra flags:

```bash
openssl req -x509 \
  -newkey ec \
  -pkeyopt ec_paramgen_curve:P-256 \
  -keyout /etc/sarek/key.pem \
  -out /etc/sarek/cert.pem \
  -sha256 \
  -days 365 \
  -nodes \
  -subj "/CN=sarek" \
  -addext "subjectAltName=DNS:sarek.local,IP:192.168.1.10"
```

Restrict permissions on the private key:

```bash
chmod 600 /etc/sarek/key.pem
```

### Let's Encrypt (Production)

```bash
certbot certonly --standalone -d vault.example.com
# Certificates land at:
#   /etc/letsencrypt/live/vault.example.com/fullchain.pem  (cert)
#   /etc/letsencrypt/live/vault.example.com/privkey.pem    (key)
```

Pass those paths to `--cert` and `--key`.

### TLS Group

In TLS 1.3, the certificate (P-256 ECDSA above) and the key exchange are independent. The certificate authenticates the server's identity; the key exchange establishes the session's shared secret for forward secrecy — a separate negotiation.

The server advertises `X25519MLKEM768:X25519` as its preferred key exchange group, providing a post-quantum hybrid key exchange for all connections. No special certificate type is needed for this; a standard P-256 or RSA cert works alongside it. OpenSSL 3.5+ and a compatible client (e.g. curl built against OpenSSL 3.5+) will negotiate the hybrid group automatically; older clients fall back to plain X25519.

---

## First-Run Bootstrap

The database directory (`db.path`) must exist and be writable before starting.

```bash
sudo mkdir -p /var/lib/sarek
sudo chown $(whoami) /var/lib/sarek
```

On first start, `sarek` detects an empty database and runs an interactive bootstrap:

```
sarek: first-run bootstrap — creating database and system trays
Admin password:
Confirm password:
sarek: bootstrap complete
```

Bootstrap creates:
- `system` tray — Level3 hybrid tray, PWENC-encrypted with the admin password
- `system-token` tray — Level2 hybrid tray, used to sign Bearer tokens
- An admin user record with full `/*` access assertion

---


## Running the Server

```
Usage: sarek [OPTIONS]

Options:
  --config <path>   Path to sarek.yml (default: /etc/sarek.yml)
  --cert   <path>   TLS certificate PEM (enables HTTPS)
  --key    <path>   TLS private key PEM  (enables HTTPS)
  --dev             Plain HTTP, no TLS (development only)
  --help            Show this message
```

```bash
sarek --cert /etc/sarek/cert.pem --key /etc/sarek/key.pem
```

**Custom config + TLS:**

```bash
sarek --config /opt/sarek/sarek.yml \
      --cert /opt/sarek/cert.pem \
      --key  /opt/sarek/key.pem
```

**Development/Debug (plain HTTP):**

```bash
sarek --config ./sarek.yml --dev
```

`--cert` and `--key` must always be supplied together. `--dev` suppresses TLS regardless of whether `--cert`/`--key` are also present.

---

## Logging

`sarek` uses [spdlog](https://github.com/gabime/spdlog) for structured logging. All server events are written to a rotating log file at INFO level.

### Log file location

```
/var/log/sarek/sarek.log
```

The directory must exist before starting the server:

```bash
sudo mkdir -p /var/log/sarek
sudo chown $(whoami) /var/log/sarek   # or the user sarek runs as
```

The log rotates automatically when it reaches **10 MB**, keeping the five most recent files:

```
/var/log/sarek/sarek.log        ← current
/var/log/sarek/sarek.log.1
/var/log/sarek/sarek.log.2
/var/log/sarek/sarek.log.3
/var/log/sarek/sarek.log.4
```

### Console output in development mode

When started with `--dev`, log messages are also written to `stderr` in addition to the log file. Production runs (with `--cert`/`--key`) write only to the file.

### Log format

```
[YYYY-MM-DD HH:MM:SS.mmm] [LEVEL] message
```

Example output:

```
[2026-03-09 14:22:01.043] [info ] config loaded from /etc/sarek.yml
[2026-03-09 14:22:01.044] [info ] db_path=/var/lib/sarek port=8443
[2026-03-09 14:22:01.312] [info ] db.open: path=/var/lib/sarek
[2026-03-09 14:22:01.315] [info ] server started successfully on port 8443 (HTTPS)
[2026-03-09 14:22:05.801] [info ] [cmd=login] user=admin addr=127.0.0.1
[2026-03-09 14:22:06.112] [info ] [cmd=create] user=admin path=/team-a/db-password size=7 addr=127.0.0.1
[2026-03-09 14:22:07.240] [info ] secret.decrypt: path=/team-a/db-password object_id=4831... tray=uuid... user=admin
[2026-03-09 14:22:07.241] [info ] cache.put: object_id=4831... user=admin
[2026-03-09 14:22:07.241] [info ] cache.state: entries=1
[2026-03-09 14:22:07.800] [info ] [cmd=read] user=admin path=/team-a/db-password addr=127.0.0.1
[2026-03-09 14:22:07.801] [debug] cache.hit: object_id=4831...
```

### Log levels

| Level | Events |
|-------|--------|
| `info` | All REST commands, server lifecycle, bootstrap, DB open/close, tray/secret/user operations, cache state, token registration, single-token revocation, expired-token purge |
| `warn` | Rejected login attempts (`[cmd=login] REJECTED`), unexpected transaction aborts (`db.txn.abort`), user lock operations, revoked/not-found token use, bulk token revocation (`revoke-tokens`, `revoke-all`) |
| `error` | Failed startup, config errors, BDB errors, unhandled server exceptions |
| `debug` | Cache hits, transaction commits — high-frequency events omitted from normal output |

All levels at `debug` and above are written to the log file. To filter interactively:

```bash
# Watch all INFO+ events in real time
tail -f /var/log/sarek/sarek.log

# Show only warnings and errors
grep -E '\[(warn|error)\]' /var/log/sarek/sarek.log

# Audit: all login events (success and failure)
grep 'cmd=login' /var/log/sarek/sarek.log

# Audit: all decrypt events (data access with user attribution)
grep 'secret.decrypt' /var/log/sarek/sarek.log

# Audit: all events for a specific user
grep 'user=alice' /var/log/sarek/sarek.log
```

### What is logged

Every REST command is logged with the authenticated username and client IP address. Sensitive values (passwords, tokens, secret data) are never logged.

| Event | Level | Details logged |
|-------|-------|----------------|
| Login success | info | username, client IP |
| Login failure | warn | username, client IP |
| Logout | info | username, client IP |
| Create user | info | creator, new username, client IP |
| Invite user | info | creator, new username, client IP |
| Change password | info | actor, target username, client IP |
| List users | info | username, client IP |
| Key generation | info | username, tray alias, tray type, client IP |
| List/get/export tray | info | username, alias, client IP |
| Create secret | info | username, vault path, size, client IP |
| Read secret (decrypt) | info | vault path, object ID, tray ID, username |
| Read secret (cache hit) | debug | object ID |
| Cache population | info | object ID, username, total cache entries |
| Create link | info | actor, link path, target path |
| Create link | info | vault paths, username |
| Token registered at login | info | token_id, username |
| Token used after revocation | warn | token_id, username |
| Token used but not found in DB | warn | token_id, username |
| Single token revoked | info | token_id |
| All tokens for user revoked | warn | username, count |
| All tokens revoked | warn | count |
| Expired tokens purged (hourly) | info | count |
| Health check | info | client IP |
| DB open | info | environment path, each database name |
| DB close | info | — |
| BDB error | error | BDB prefix, message |
| Server start/stop | info | port, protocol |
| Bootstrap | info | lifecycle messages |

---

## Authentication

All endpoints except `GET /health` require a Bearer token obtained from `POST /login`.

Tokens are raw binary, returned base64-encoded in the `token` field. Pass them back in the `Authorization` header:

```
Authorization: Bearer <base64-encoded token>
```

Tokens are signed with the `system-token` tray (ECDSA P-256 + Dilithium). The server verifies the signature, checks the `usr:<username>` assertion, and then checks the `manage_token` database for revocation on every authenticated request.

---

## Token Revocation

The server tracks every issued token in a `manage_token` BDB database (keyed by the token's UUID). On each authenticated request the token's revocation status is checked after signature verification.

| Status | HTTP response |
|--------|---------------|
| Valid (found, not revoked) | Request proceeds normally |
| Not found in DB | `401 {"error":"invalid token, please login"}` |
| Found and revoked | `401 {"error":"token revoked, please login"}` |

When a client (amanda) receives either of these specific 401 messages it automatically deletes `$HOME/.sarek` so the user is prompted to re-login on the next command.

**Issued token lifetime**: tokens expire after 24 hours. Expired records are purged from the `manage_token` database by a background thread that runs every hour.

**Admin revocation routes** (see [API Reference](#api-reference) below):

| Operation | Endpoint |
|-----------|----------|
| List all tokens | `GET /admin/tokens` |
| Revoke one token | `DELETE /admin/tokens/:token_id` |
| Revoke all tokens for one user | `DELETE /admin/tokens?username=<name>` |
| Revoke all tokens | `DELETE /admin/tokens` |

---

## API Reference

Base URL: `https://<host>:<port>`

### `POST /login`

Authenticate and receive a token.

**Request body:**
```json
{ "username": "alice", "password": "s3cr3t" }
```

**Response `200`:**
```json
{ "token": "<base64>", "username": "alice" }
```

**Response `401`:** Invalid credentials.

---

### `DELETE /logout`

Invalidates the session on the client side (the server is stateless; the client should discard the token).

**Response `200`:**
```json
{ "status": "logged out" }
```

---

### `POST /users` *(admin only)*

Create a new user account.

**Request body:**
```json
{
  "username": "bob",
  "password": "b0bsecret",
  "assertions": ["slc:/team-a/*"]
}
```

`assertions` is optional. The server always adds `usr:<username>` automatically. Admin token (assertion `/*`) is required.

**Response `200`:**
```json
{ "username": "bob", "user_id": 12345678 }
```

---

### `POST /trays`

Generate a new cryptographic tray for the authenticated user.

**Request body:**
```json
{ "alias": "my-tray", "type": "level3" }
```

**Tray types:**

| Type | KEM | Signature |
|------|-----|-----------|
| `level0` | X25519 | Ed25519 |
| `level1` | P-384 | ECDSA P-384 |
| `level2` | X25519 + Kyber-768 | Ed25519 + Dilithium3 |
| `level3` | X25519 + Kyber-768 | Ed25519 + Dilithium3 (stronger params) |
| `level5` | P-521 + Kyber-1024 | ECDSA P-521 + Dilithium5 |

**Response `200`:** Full tray object including per-slot public keys (base64-encoded). Secret keys are never returned.

---

### `GET /trays`

List the aliases of all trays owned by the authenticated user.

**Response `200`:**
```json
{ "trays": ["my-tray", "team-tray"] }
```

---

### `GET /trays/:alias`

Get the public details of a tray by alias.

**Response `200`:**
```json
{
  "id":      "uuid-v8-string",
  "alias":   "my-tray",
  "type":    "level3",
  "created": 1700000000,
  "expires": 0,
  "slots": [
    { "alg": "x25519",      "pk_b64": "...", "has_sk": false },
    { "alg": "kyber768",    "pk_b64": "...", "has_sk": false },
    { "alg": "ed25519",     "pk_b64": "...", "has_sk": false },
    { "alg": "dilithium3",  "pk_b64": "...", "has_sk": false }
  ]
}
```

---

### `POST /secrets/:path`

Store an encrypted secret at the given vault path.

- `:path` is the full vault path, e.g. `/team-a/db-password`. The leading `/` is implicit in the URL (`/secrets/team-a/db-password`).
- The request body is the raw secret bytes.
- `Content-Type` is stored as the secret's MIME type and returned on retrieval.
- Optional query param `?tray=<alias>` selects the encryption tray (defaults to `system-token`).
- The authenticated user must have a `slc:` assertion that covers the path, or `/*`.

**Response `201`:**
```json
{ "status": "created" }
```

---

### `GET /secrets/:path`

Retrieve and decrypt a secret. Returns the raw bytes with the original `Content-Type`.

Follows symlinks (link records) transparently.

---

### `GET /secrets/:path/meta`

Return metadata for a secret without decrypting it.

**Response `200`:**
```json
{
  "object_id": 9876543,
  "created":   1700000000,
  "size":      42,
  "mimetype":  "text/plain",
  "tray_id":   "uuid-v8-string"
}
```

If the path is a link, `link_path` is also present.

---

### `GET /secrets?prefix=/team-a/`

List vault paths visible to the authenticated user, optionally filtered by prefix.

**Response `200`:**
```json
{ "secrets": ["/team-a/db-password", "/team-a/api-key"] }
```

---

### `POST /links`

Create a symlink from one vault path to another.

**Request body:**
```json
{ "target": "/team-a/db-password", "link": "/shared/db-password" }
```

The token must have scope over both `target` and `link`.

**Response `201`:**
```json
{ "status": "created" }
```

---

### `GET /health`

Unauthenticated liveness check.

**Response `200`:**
```json
{ "status": "healthy" }
```

---

### `GET /admin/tokens` *(admin only)*

List all issued tokens with their status.

**Response `200`:** JSON array:
```json
[
  {
    "token_id": "a1b2c3d4-e5f6-4abc-8def-1234567890ab",
    "username": "alice",
    "created":  1741694400,
    "expiry":   1741780800,
    "revoked":  false
  }
]
```

---

### `DELETE /admin/tokens/:token_id` *(admin only)*

Revoke a single token by UUID.

**Response `200`:**
```json
{ "revoked": "a1b2c3d4-e5f6-4abc-8def-1234567890ab" }
```

**Response `404`:** Token not found.

---

### `DELETE /admin/tokens?username=<name>` *(admin only)*

Revoke all active tokens for one user.

**Response `200`:**
```json
{ "revoked": 2, "username": "alice" }
```

---

### `DELETE /admin/tokens` *(admin only)*

Revoke all active tokens in the system. All users must re-login.

**Response `200`:**
```json
{ "revoked": 7, "message": "all tokens revoked" }
```

---

## YAML Secret Extraction

The server can extract a single value from a stored YAML secret without requiring the client to download and parse the full document. This is useful when a secret stores a structured credentials file and you need only one field — for example, pulling a password out of a multi-key YAML record.

### Endpoint

```
GET /secrets/:path/yaml-extract?ypath=<expression>
```

Auth: Bearer token required; path scope rules apply as for `GET /secrets/:path`.

The `ypath` query parameter is a [YPATH expression](https://github.com/pantoniou/libfyaml) compatible with the [libfyaml](https://github.com/pantoniou/libfyaml) library. YPATH is a JSONPath-like syntax for YAML documents; simple key paths take the form `/key/subkey`.

### Behaviour

| Condition | Response |
|-----------|----------|
| Secret not found or path out of scope | `404` / `403` |
| No mimetype stored for secret | `400 {"error": "no mimetype stored for this secret"}` |
| Mimetype is not a YAML type | `400 {"error": "mimetype '<type>' is not a YAML type"}` |
| Secret data is not valid YAML | `400 {"error": "secret data is not valid YAML"}` |
| YPATH expression not found in document | `404 {"error": "ypath '<expr>' not found in document"}` |
| Scalar node matched | `200 text/plain` — the scalar value, no trailing newline |
| Non-scalar node matched (mapping or sequence) | `200 application/yaml` — the sub-document serialised to YAML |

Accepted YAML MIME types: `application/yaml`, `application/x-yaml`, `application/yml`, `text/yaml`.

### curl Example

Given a secret at `/alice/secrets/shopify` with content:

```yaml
data:
  what: Shopify store admin login
  who: dave@example.com
  password: h4rdp4ss!
```

Extract the password field:

```bash
curl $CACERT \
  -H "Authorization: Bearer $TOKEN" \
  "https://sarek.local:8443/secrets/alice/secrets/shopify/yaml-extract?ypath=%2Fdata%2Fpassword"
# output: h4rdp4ss!
```

`/data/password` must be percent-encoded as `%2Fdata%2Fpassword` in the query string. The `amanda yaml-extract` command handles this automatically.

---

## curl Examples

Set a few shell variables first:

```bash
HOST=https://sarek.local:8443
# For a self-signed cert, add -k to skip verification, or --cacert /etc/sarek/cert.pem
CACERT="--cacert /etc/sarek/cert.pem"
```

### Health check

```bash
curl $CACERT "$HOST/health"
```

### Login

```bash
TOKEN=$(curl -s $CACERT -X POST "$HOST/login" \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"s3cr3t"}' \
  | jq -r .token)

echo "Token: $TOKEN"
```

### Store a secret (plain text)

```bash
curl $CACERT -X POST "$HOST/secrets/team-a/db-password" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: text/plain" \
  --data-raw "hunter2"
```

### Store a secret (binary file)

```bash
curl $CACERT -X POST "$HOST/secrets/team-a/keyfile" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/octet-stream" \
  --data-binary @/path/to/keyfile
```

### Store a secret using a specific tray

```bash
curl $CACERT -X POST "$HOST/secrets/team-a/db-password?tray=my-tray" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: text/plain" \
  --data-raw "hunter2"
```

### Retrieve a secret

```bash
curl $CACERT "$HOST/secrets/team-a/db-password" \
  -H "Authorization: Bearer $TOKEN"
```

### Retrieve secret metadata

```bash
curl $CACERT "$HOST/secrets/team-a/db-password/meta" \
  -H "Authorization: Bearer $TOKEN" | jq .
```

### List secrets under a prefix

```bash
curl $CACERT "$HOST/secrets?prefix=/team-a/" \
  -H "Authorization: Bearer $TOKEN" | jq .
```

### Create a link

```bash
curl $CACERT -X POST "$HOST/links" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"target":"/team-a/db-password","link":"/shared/db-password"}'
```

### Extract a value from a YAML secret

```bash
# ypath must be percent-encoded: /data/password → %2Fdata%2Fpassword
curl $CACERT "$HOST/secrets/alice/secrets/shopify/yaml-extract?ypath=%2Fdata%2Fpassword" \
  -H "Authorization: Bearer $TOKEN"
# output: h4rdp4ss!
```

### Create a user (admin)

```bash
curl $CACERT -X POST "$HOST/users" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"username":"bob","password":"b0bsecret","assertions":["slc:/team-a/*"]}'
```

### Create a tray

```bash
curl $CACERT -X POST "$HOST/trays" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"alias":"team-tray","type":"level3"}' | jq .
```

### List trays

```bash
curl $CACERT "$HOST/trays" \
  -H "Authorization: Bearer $TOKEN" | jq .
```

### Logout

```bash
curl $CACERT -X DELETE "$HOST/logout" \
  -H "Authorization: Bearer $TOKEN"
```

### List all tokens (admin)

```bash
curl $CACERT "$HOST/admin/tokens" \
  -H "Authorization: Bearer $TOKEN" | jq .
```

### Revoke a single token (admin)

```bash
TOKEN_ID="a1b2c3d4-e5f6-4abc-8def-1234567890ab"
curl $CACERT -X DELETE "$HOST/admin/tokens/$TOKEN_ID" \
  -H "Authorization: Bearer $TOKEN"
```

### Revoke all tokens for a user (admin)

```bash
curl $CACERT -X DELETE "$HOST/admin/tokens?username=alice" \
  -H "Authorization: Bearer $TOKEN"
```

### Revoke all tokens (admin)

```bash
curl $CACERT -X DELETE "$HOST/admin/tokens" \
  -H "Authorization: Bearer $TOKEN"
```

---

## Access Control

A simple token assertion system controls what paths a user can read and write:

| Assertion | Access |
|-----------|--------|
| `/*` | Full admin access to all paths |
| `slc:/team-a/*` | All paths under `/team-a/` |
| `slc:/team-a/db-password` | Exactly that one path |
| `usr:<username>` | Identity marker (always present, not a path grant) |

The admin user created during bootstrap receives `/*`. When creating additional users, supply the appropriate `slc:` assertions in the `assertions` array of `POST /users`.




