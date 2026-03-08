# sarek — Post-Quantum Secrets Vault Server

`sarek` is the server binary for the SAREK secrets vault. It exposes a secure REST API for managing cryptographic key materials and encrypted secrets.

---

## Table of Contents

1. [Configuration](#configuration)
2. [First-Run Bootstrap](#first-run-bootstrap)
3. [TLS Setup](#tls-setup)
4. [Running the Server](#running-the-server)
5. [Authentication](#authentication)
6. [API Reference](#api-reference)
7. [curl Examples](#curl-examples)

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

The server advertises `X25519MLKEM768:X25519` as its preferred TLS KEM group, providing a post-quantum hybrid key exchange for all connections. OpenSSL 3.5+ and a compatible client 
(e.g. curl built against OpenSSL 3.5+) will negotiate the hybrid group automatically; older clients fall back to plain X25519.

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

## Authentication

All endpoints except `GET /health` require a Bearer token obtained from `POST /login`.

Tokens are raw binary, returned base64-encoded in the `token` field. Pass them back in the `Authorization` header:

```
Authorization: Bearer <base64-encoded token>
```

Tokens are signed with the `system-token` tray (ECDSA P-256 + Dilithium). The server verifies the signature and checks the `usr:<username>` assertion on every request.

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




