#pragma once

#include "db/db.hpp"
#include "cache/lru_cache.hpp"
#include "bootstrap/bootstrap.hpp"    // hash_password
#include "bootstrap/user_record.hpp"
#include "auth/auth.hpp"              // load_tray_by_alias, load_user

#include <crystals/crystals.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace sarek {

// ---------------------------------------------------------------------------
// MetadataRecord — stored in DB:metadata, keyed by object_id (uint64 BE)
// ---------------------------------------------------------------------------
struct MetadataRecord {
    uint64_t    object_id  = 0;
    int64_t     created    = 0;    // unix epoch
    uint64_t    size       = 0;    // plaintext byte count
    std::string mimetype;
    std::string tray_id;           // UUID string of the encrypting tray
    std::string link_path;         // non-empty → this record is a symlink
    uint64_t    creator_id = 0;    // user_id of creator; 0 = unknown (pre-schema records)
};

std::vector<uint8_t> pack_metadata(const MetadataRecord& m);
MetadataRecord       unpack_metadata(const std::vector<uint8_t>& data);

// ---------------------------------------------------------------------------
// Path validation
// ---------------------------------------------------------------------------

// Throws std::invalid_argument if path is not valid:
//   - must start with '/'
//   - must not end with '/' (except root "/", which is invalid for a secret)
//   - must not contain "//" or "." or ".." components
void validate_path(const std::string& path);

// ---------------------------------------------------------------------------
// Unarmored OBIWAN encrypt / decrypt
// Stores raw wire bytes (no base64) suitable for BDB values.
// ---------------------------------------------------------------------------

// Encrypt plaintext with the tray's hybrid KEM (slots[0]=KEM-classical, slots[1]=KEM-PQ).
// Returns raw OBIWAN wire bytes (SHAKE256/AES-256-GCM).
std::vector<uint8_t> obiwan_encrypt(const std::vector<uint8_t>& plaintext, const Tray& tray);

// Decrypt raw OBIWAN wire bytes using the tray's private keys. Throws on failure.
std::vector<uint8_t> obiwan_decrypt(const std::vector<uint8_t>& wire, const Tray& tray);

// ---------------------------------------------------------------------------
// UserService
// ---------------------------------------------------------------------------

// Create a new user in DB:user. Throws if the username already exists.
void create_user(SarekEnv& env,
                 const std::string& username,
                 const std::string& password,
                 uint32_t           flags,
                 const std::vector<std::string>& assertions,
                 uint64_t           user_id,
                 uint8_t            scrypt_n_log2 = 20);

// Set the locked flag on a user. Throws if not found.
void lock_user(SarekEnv& env, const std::string& username);

// Return all (username, UserRecord) pairs in BDB key order.
std::vector<std::pair<std::string, UserRecord>> list_users(SarekEnv& env);

// Update the password hash for an existing user. Throws if not found.
void update_user_password(SarekEnv& env,
                          const std::string& username,
                          const std::string& new_password,
                          uint8_t scrypt_n_log2 = 20);

// ---------------------------------------------------------------------------
// TrayService
// ---------------------------------------------------------------------------

// Store a plain (unencrypted, enc=0) tray in DB:tray and DB:tray_alias.
// Uses tray.alias as the alias key. Throws if alias already exists.
void store_tray(SarekEnv& env, const Tray& tray, uint64_t owner_user_id);

// Load a plain tray from the DB by its 16-byte raw UUID key.
// Throws if not found or if PWENC-encrypted.
Tray get_tray_by_id(SarekEnv& env, const void* tray_uuid_16, size_t len = 16);

// List all tray aliases owned by owner_user_id.
std::vector<std::string> list_trays_for_user(SarekEnv& env, uint64_t owner_user_id);

// List all tray aliases in the DB (admin view).
std::vector<std::string> list_all_trays(SarekEnv& env);

// ---------------------------------------------------------------------------
// SecretService
// ---------------------------------------------------------------------------

// Write plaintext → encrypted data blob, metadata record, and path entry, all
// in one transaction. Throws if path already exists or is invalid.
void create_secret(SarekEnv&                  env,
                   const std::string&          path,
                   const std::vector<uint8_t>& plaintext,
                   const Tray&                 tray,
                   const std::string&          mimetype = "application/octet-stream",
                   uint64_t                    creator_id = 0);

// Read and decrypt a secret. Follows link chains (up to 8 hops).
// If data_cache is non-null, checks it before decryption and populates on miss.
std::vector<uint8_t> read_secret(
    SarekEnv& env, const std::string& path,
    LruCache<uint64_t, std::vector<uint8_t>>* data_cache = nullptr);

// Return the metadata for a path. Does NOT follow links (returns the link record itself).
MetadataRecord read_metadata(SarekEnv& env, const std::string& path);

// List all vault paths that begin with prefix (empty = all paths).
std::vector<std::string> list_secrets(SarekEnv& env, const std::string& prefix = "");

// Create a symlink: link_path → target_path. Both must be valid paths; link_path
// must not already exist; target_path need not exist yet.
void create_link(SarekEnv&          env,
                 const std::string& target_path,
                 const std::string& link_path);

// Remove a symlink. Deletes the DB:path entry and DB:metadata record for
// link_path. Throws if link_path does not exist or is not a symlink.
void delete_link(SarekEnv& env, const std::string& link_path);

// ---------------------------------------------------------------------------
// TokenRecord / TokenStatus / TokenService
// ---------------------------------------------------------------------------

struct TokenRecord {
    std::string token_id;   // hex UUID string (36 chars)
    std::string username;
    int64_t     created = 0;   // unix epoch seconds
    int64_t     expiry  = 0;   // unix epoch seconds
    bool        revoked = false;
};

enum class TokenStatus { Valid, NotFound, Revoked };

// Register a newly issued token in manage_token DB.
void register_token(SarekEnv& env,
                    const std::string& token_id,
                    const std::string& username,
                    int64_t created,
                    int64_t expiry);

// Check revocation status of a token by its UUID string.
TokenStatus check_token(SarekEnv& env, const std::string& token_id);

// Revoke a single token by UUID string. Returns false if not found.
bool revoke_token(SarekEnv& env, const std::string& token_id);

// Revoke all tokens for a given username. Returns count revoked.
int revoke_tokens_for_user(SarekEnv& env, const std::string& username);

// Revoke all tokens. Returns count revoked.
int revoke_all_tokens(SarekEnv& env);

// List all token records (admin view).
std::vector<TokenRecord> list_tokens(SarekEnv& env);

// Delete records where expiry < now. Called by background cleanup thread.
int purge_expired_tokens(SarekEnv& env);

// ---------------------------------------------------------------------------
// WrapService — one-time secret delivery with TTL
// ---------------------------------------------------------------------------

struct WrappedRecord {
    uint64_t user_id = 0;
    int64_t  expiry  = 0;   // unix epoch seconds
};

// Create a wrapped secret. Encrypts plaintext with the "wrap" tray alias,
// stores in wrapped+wrapper_lookup DBs. Returns base64url-encoded 16-byte token.
// ttl_secs must be in [600, 432000] (10 min – 5 days).
std::string create_wrapped(SarekEnv& env, uint64_t user_id,
                           const std::vector<uint8_t>& plaintext,
                           int64_t ttl_secs);

// Redeem a wrapping token. Atomically deletes both DB records on success.
// Throws on: not found, expired, "wrap" tray not found, decryption failure.
std::vector<uint8_t> unwrap(SarekEnv& env, const std::string& base64url_token);

// Delete wrapped+wrapper_lookup records where expiry < now.
int purge_expired_wrapped(SarekEnv& env);

// ---------------------------------------------------------------------------
// Admin operations
// ---------------------------------------------------------------------------

struct DeleteUserResult {
    int trays_deleted   = 0;
    int secrets_deleted = 0;
};

// Delete a user and cascade-delete all owned trays and associated secrets.
// Throws if the user is not found. Does NOT permit deleting admin-flagged users
// (caller must check before calling).
DeleteUserResult delete_user(SarekEnv& env, const std::string& username);

} // namespace sarek
