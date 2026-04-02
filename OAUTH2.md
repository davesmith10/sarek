# OAuth2 Client Credentials Support

SAREK supports the [OAuth 2.0 Client Credentials Flow](https://datatracker.ietf.org/doc/html/rfc6749#section-4.4)
as an alternative authentication path alongside the existing bespoke token system. SAREK acts as its
own Authorization Server — no external IdP is involved.

---

## Overview

```
Admin                      Server                        Service / Script
  │                          │                                │
  │  oauth-setup --username  │                                │
  ├─────────────────────────►│  store hashed secret in DB    │
  │  ← client_id + secret    │                                │
  │                          │                                │
  │                          │  POST /oauth/token             │
  │                          │◄───────────────────────────────┤
  │                          │  grant_type=client_credentials │
  │                          │  client_id + client_secret     │
  │                          │                                │
  │                          │  ← JWT (Bearer token)          │
  │                          │───────────────────────────────►│
  │                          │                                │
  │                          │  GET /secrets/...              │
  │                          │◄───────────────────────────────┤
  │                          │  Authorization: Bearer <jwt>   │
```

---

## Server Endpoints

### `POST /oauth/token`

Exchanges client credentials for a signed JWT access token.

**Authentication:** None required.

**Request body** — either `application/json` or `application/x-www-form-urlencoded`:

| Field | Required | Description |
|-------|----------|-------------|
| `grant_type` | yes | Must be `client_credentials` |
| `client_id` | yes | Issued by `oauth-setup` |
| `client_secret` | yes | Issued by `oauth-setup` (shown once) |
| `ttl` | no | Token lifetime: integer seconds or string (`"1h"`, `"30m"`, `"2d"`, `"3600s"`). Default: `3600` (1 hour) |

**Response:**
```json
{
  "access_token": "<jwt>",
  "token_type":   "Bearer",
  "expires_in":   3600
}
```

**Errors:**

| Status | `error` | Cause |
|--------|---------|-------|
| 400 | `unsupported_grant_type` | `grant_type` ≠ `client_credentials` |
| 400 | `invalid_request` | Missing `client_id` or `client_secret`, or invalid `ttl` |
| 400 | (parse error) | Malformed request body |
| 401 | `invalid_client` | Unknown `client_id` or wrong `client_secret` |
| 500 | (server error) | Signing key unavailable or internal failure |

Response headers include `Cache-Control: no-store` and `Pragma: no-cache` per RFC 6749 §5.1.

---

### `POST /admin/oauth2/setup`

Creates OAuth credentials for an existing SAREK user. **Admin only.**

**Request body:**
```json
{ "username": "<existing username>" }
```

**Response:**
```json
{
  "client_id":     "<32 hex characters>",
  "client_secret": "<base64 string>"
}
```

The `client_secret` is shown **once only** and never stored in plaintext. Store it securely.

---

### `DELETE /admin/oauth2/revoke`

Revokes OAuth credentials for a user. Existing JWTs issued before revocation remain valid until
they expire (JWTs are stateless). **Admin only.**

**Request body:**
```json
{ "username": "<username>" }
```

**Response:**
```json
{ "status": "revoked" }
```
or `{ "status": "not_found" }` if no credentials existed.

---

## JWT Token Format

Tokens are signed with HMAC-SHA256 (HS256) using a 32-byte key stored in the SAREK database
(`oauth_signing_key` entry). The signing key is generated on first server start and is stable
across restarts.

**Standard claims:**

| Claim | Value |
|-------|-------|
| `iss` | `sarek` |
| `aud` | `sarek` |
| `sub` | username |
| `iat` | issued-at (Unix timestamp) |
| `exp` | expiry (Unix timestamp) |
| `jti` | random UUID per token |

**SAREK-specific claim:**

| Claim | Value |
|-------|-------|
| `asr` | Array of assertion strings (e.g. `["usr:alice", "slc:/team-a/*"]`) |

Assertions are loaded from the user's account at the moment of token issuance. They govern
access scope in exactly the same way as bespoke tokens.

---

## Using Bearer Tokens

The server accepts two token types in the `Authorization: Bearer` header:

| Type | Detection | Format |
|------|-----------|--------|
| Bespoke token | Bearer value does NOT start with `eyJ` | Binary blob, base64-encoded |
| OAuth JWT | Bearer value starts with `eyJ` and contains `.` | Raw JWT compact string |

Unlike bespoke tokens, OAuth JWTs are sent **directly** as the Bearer value without any extra
base64 wrapping. This is standard RFC 6750 behaviour.

---

## curl Examples

### Obtain a token

```bash
# JSON body
TOKEN=$(curl -s -k -X POST https://localhost:8443/oauth/token \
  -H "Content-Type: application/json" \
  -d '{"grant_type":"client_credentials","client_id":"<id>","client_secret":"<secret>"}' \
  | jq -r .access_token)

# Form-urlencoded body
TOKEN=$(curl -s -k -X POST https://localhost:8443/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=<id>&client_secret=<secret>" \
  | jq -r .access_token)
```

### Use the token

```bash
# Health check
curl -k -H "Authorization: Bearer $TOKEN" https://localhost:8443/health

# List secrets
curl -k -H "Authorization: Bearer $TOKEN" https://localhost:8443/secrets

# Read a secret
curl -k -H "Authorization: Bearer $TOKEN" https://localhost:8443/secrets/myapp/db-password
```

### Custom TTL

```bash
curl -s -k -X POST https://localhost:8443/oauth/token \
  -H "Content-Type: application/json" \
  -d '{"grant_type":"client_credentials","client_id":"<id>","client_secret":"<secret>","ttl":"8h"}'
```

---

## Amanda CLI Commands

### `oauth-setup` — create credentials (admin)

```
amanda oauth-setup --username <name> [--save]
```

Calls `POST /admin/oauth2/setup` and prints the `client_id` and `client_secret`.

With `--save`, the `client_id` is written to `~/.sarekrc` as `oauth_client_id` so
`login-oauth` can find it automatically.

**Example:**
```
$ amanda oauth-setup --username deploy-bot --save
client_id:     a3f7b2e491c84d6e...
client_secret: vX3rNqZ8...

Store these securely. The client_secret will not be shown again.
client_id saved to ~/.sarekrc
```

---

### `login-oauth` — authenticate via OAuth

```
amanda login-oauth [--client-id <id>] [--ttl <duration>]
```

Reads `client_id` from `~/.sarekrc` (or `--client-id` flag), prompts for the client
secret, exchanges credentials at `/oauth/token`, and stores the JWT in `~/.sarek.oauth`.

The OAuth token takes precedence over any bespoke token (`~/.sarek`) when both are present.

**Example:**
```
$ amanda login-oauth
Enter client secret:
Logged in via OAuth (expires in 3600s). Token stored in ~/.sarek.oauth
```

---

### `oauth-revoke` — revoke credentials (admin)

```
amanda oauth-revoke --username <name>
```

Calls `DELETE /admin/oauth2/revoke`. Note: any JWTs already issued remain valid until
their `exp` claim. Rotate secrets rather than revoke if immediate invalidation is needed
(revoke then re-setup).

---

### `logout`

```
amanda logout
```

Deletes both `~/.sarek` (bespoke) and `~/.sarek.oauth` (OAuth), and calls `DELETE /logout`
to invalidate the bespoke token server-side.

---

## Database

OAuth state is stored in the `oauth_client` BDB database (11th database in the environment):

| Key | Value (msgpack) |
|-----|-----------------|
| `user:<username>` | `{client_id, created}` — reverse lookup |
| `<client_id>` | `{username, scrypt_hash_of_secret, created}` — primary record |

The HMAC signing key is stored as a raw 32-byte value under the key `oauth_signing_key`
in the same database. It is generated once by `oauth_init_signing_key()` and loaded by
`oauth_load_signing_key()` at every server start.

---

## Security Notes

- **Client secret hashing**: secrets are hashed with scrypt (same parameters as user
  passwords) before storage. The plaintext secret is never persisted.
- **Stateless JWTs**: OAuth JWTs are not tracked in the `manage_token` database and
  cannot be individually revoked server-side. Use a short TTL for automated accounts.
- **Key storage**: the HMAC signing key lives in the BDB database. Protect the database
  files with appropriate filesystem permissions.
- **Assertions at issuance**: JWT claims reflect the user's assertions at the moment the
  token is issued. Changing a user's assertions does not affect already-issued tokens.
- **Token file permissions**: `~/.sarek.oauth` is created with mode `0600`.
