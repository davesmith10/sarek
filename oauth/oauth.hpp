#pragma once

#include "db/db.hpp"
#include "auth/auth.hpp"          // TokenClaims

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace sarek {

// ---------------------------------------------------------------------------
// OAuthClientRecord — one registered OAuth2 client per user
// ---------------------------------------------------------------------------
struct OAuthClientRecord {
    std::string username;
    std::string client_id;
    int64_t     created = 0;   // unix epoch seconds
};

// ---------------------------------------------------------------------------
// Signing key management (called by run_server on startup)
// ---------------------------------------------------------------------------

// Generate a fresh 32-byte HMAC signing key and store it in oauth_client DB.
// No-op if a key already exists (idempotent — safe to call on every startup).
void oauth_init_signing_key(SarekEnv& env, const Tray& system_tray);

// Load the HMAC signing key from oauth_client DB.
// Throws std::runtime_error if not found (bootstrap not run).
std::vector<uint8_t> oauth_load_signing_key(SarekEnv& env, const Tray& system_tray);

// ---------------------------------------------------------------------------
// Client credential CRUD
// ---------------------------------------------------------------------------

// Create a client_id / client_secret pair for an existing user.
// Returns {client_id, client_secret} (plain-text secret, shown once).
// Throws if the user is not found or already has OAuth credentials.
std::pair<std::string,std::string> oauth_setup_client(
    SarekEnv& env, const std::string& username);

// Delete OAuth credentials for a user.
// Returns false if no credentials were found (idempotent).
bool oauth_revoke_client(SarekEnv& env, const std::string& username);

// Verify client_id + client_secret; return the owning username on success.
// Throws std::runtime_error with a deliberately vague message on any failure.
std::string oauth_authenticate_client(SarekEnv& env,
    const std::string& client_id, const std::string& client_secret);

// ---------------------------------------------------------------------------
// JWT issue / verify
// ---------------------------------------------------------------------------

// Issue a signed HS256 JWT for the given user+assertions.
// Returns a compact JWT string (header.payload.signature).
// Uses liboauth2's oauth2_jwt_create internally.
// ttl_secs: token lifetime in seconds (default 3600 = 1 hour).
// aud_id: deployment audience UUID used as the JWT "aud" claim; falls back to
//         "sarek" when empty (legacy / test behaviour).
std::string oauth_issue_jwt(
    const std::vector<uint8_t>& signing_key,
    const std::string& username,
    const std::vector<std::string>& assertions,
    int64_t ttl_secs = 3600,
    const std::string& aud_id = "");

// Verify a JWT signature, expiry, and (when aud_id is non-empty) audience claim.
// Throws std::runtime_error on bad signature, expiry, audience mismatch, or
// malformed payload.
// Uses cjose directly for verification.
TokenClaims oauth_verify_jwt(
    const std::vector<uint8_t>& signing_key,
    const std::string& jwt_str,
    const std::string& aud_id = "");

} // namespace sarek
