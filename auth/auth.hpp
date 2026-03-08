#pragma once

#include "db/db.hpp"
#include "bootstrap/bootstrap.hpp"    // hash_password, verify_password
#include "bootstrap/user_record.hpp"

#include <crystals/tray.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace sarek {

// Claims extracted from a validated token.
struct TokenClaims {
    std::string              username;
    std::vector<std::string> assertions;
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

// Return the user record for username, or nullopt if not found.
std::optional<UserRecord> load_user(SarekEnv& env, const std::string& username);

// Verify password. Returns the user record on success; nullopt on wrong password.
// Throws std::runtime_error if the user is not found or is locked.
std::optional<UserRecord> authenticate_user(SarekEnv& env,
                                             const std::string& username,
                                             const std::string& password);

} // namespace sarek
