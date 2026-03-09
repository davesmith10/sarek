#pragma once

#include "config/config.hpp"
#include "db/db.hpp"
#include "bootstrap/user_record.hpp"

#include <memory>
#include <string>

namespace sarek {

// Returns true if the BDB environment at cfg.db_path has not yet been bootstrapped.
bool needs_bootstrap(const SarekConfig& cfg);

// Run bootstrap with a pre-supplied password.
//   admin_password — used to PWENC-encrypt the system tray AND as the admin login password.
//   scrypt_n_log2  — scrypt cost factor: N = 2^n_log2. Default 20; use 16 for tests.
// Returns a fully-initialized SarekEnv ready for use. Throws on failure.
std::unique_ptr<SarekEnv> run_bootstrap(const SarekConfig& cfg,
                                         const std::string& admin_password,
                                         uint8_t scrypt_n_log2 = 20);

// Interactive variant: prompts for password (no-echo) and calls run_bootstrap.
std::unique_ptr<SarekEnv> run_bootstrap_interactive(const SarekConfig& cfg);

// ── Password hashing (also used by Module 5 — auth) ──────────────────────────

// Hash a password for storage. Format: "scrypt$N_log2$r$p$b64salt$b64hash"
std::string hash_password(const std::string& plaintext, uint8_t n_log2 = 20);

// Verify plaintext against stored_hash. Returns false on mismatch; throws on
// internal error.
bool verify_password(const std::string& plaintext, const std::string& stored_hash);

// ── PWENC tray decryption ──────────────────────────────────────────────────

// Decrypt a PWENC blob (as stored in DB:tray "bl" field for enc==1 records)
// using the given password. Returns the raw tray_mp::pack bytes.
// Throws std::runtime_error on bad password or corrupt data.
std::vector<uint8_t> pwenc_decrypt_blob(const std::vector<uint8_t>& blob,
                                         const std::string& password);

} // namespace sarek
