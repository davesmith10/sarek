#pragma once

#include "db/db.hpp"
#include "bootstrap/bootstrap.hpp"    // hash_password, verify_password
#include "bootstrap/user_record.hpp"

#include <crystals/crystals.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace sarek {

// Claims extracted from a validated token.
struct TokenClaims {
    std::string              username;
    std::vector<std::string> assertions;
    std::string              token_uuid;  // hex UUID v4, e.g. "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx"
};

// ---------------------------------------------------------------------------
// Token lifecycle
// ---------------------------------------------------------------------------

// Sign and issue a token for user using the system-token tray's ECDSA P-256 key.
// Assertions are stored as newline-separated bytes in the token data field.
// ttl_secs: token lifetime in seconds (default 86400 = 24 h).
// Throws if tray has no ECDSA P-256 signing slot, or if assertions exceed 256 bytes.
std::vector<uint8_t> issue_token(const UserRecord& user,
                                  const Tray& system_token_tray,
                                  int64_t ttl_secs = 86400);

// Parse and verify a token wire.
// Throws std::runtime_error on bad format, expiry, bad signature, or UUID mismatch.
TokenClaims validate_token(const std::vector<uint8_t>& wire,
                            const Tray& system_token_tray_pub);

// ---------------------------------------------------------------------------
// DB helpers
// ---------------------------------------------------------------------------

// Load a plain (enc == 0) tray from the DB by alias.
// Throws if the alias is not found or if the tray is PWENC-encrypted.
Tray load_tray_by_alias(SarekEnv& env, const std::string& alias);

// Returns true if the tray record for alias has enc == 1 (PWENC-encrypted).
// Returns false if plain or if alias not found.
bool is_tray_encrypted(SarekEnv& env, const std::string& alias);

// Decrypt a PWENC-encrypted tray from the DB using the given password.
// Throws if the alias is not found, not PWENC-encrypted, or the password is wrong.
Tray load_tray_by_alias_pwenc(SarekEnv& env, const std::string& alias,
                               const std::string& password);

// Return the user record for username, or nullopt if not found.
std::optional<UserRecord> load_user(SarekEnv& env, const std::string& username);

// Verify password. Returns the user record on success; nullopt on wrong password.
// Throws std::runtime_error if the user is not found or is locked.
std::optional<UserRecord> authenticate_user(SarekEnv& env,
                                             const std::string& username,
                                             const std::string& password);

} // namespace sarek
