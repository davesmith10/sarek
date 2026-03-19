#pragma once

#include "config/config.hpp"
#include "db/db.hpp"
#include "bootstrap/user_record.hpp"

#include <crystals/crystals.hpp>

#include <memory>
#include <string>

namespace sarek {

// Returns true if the BDB environment at cfg.db_path has not yet been bootstrapped.
bool needs_bootstrap(const SarekConfig& cfg);

// Import a system tray from a YAML file. Handles both plain (type: tray) and
// password-protected (type: secure-tray) files. For plain trays, passwd/passwd_len
// are ignored. Throws std::runtime_error on failure.
Tray import_system_tray(const std::string& path,
                         const char* passwd, size_t passwd_len);

// Deserialize the system tray from the kernel keyring (via env.get_system_tray_bytes()).
// Throws if the keyring blob has not been set on env.
Tray load_system_tray(const SarekEnv& env);

// Run bootstrap with a pre-supplied admin password and an already-imported system tray.
//   admin_password — used as the admin login password.
//   system_tray    — the Level3 system tray to store in DB and keyring.
//   scrypt_n_log2  — scrypt cost factor: N = 2^n_log2. Default 20; use 14 for tests.
// Returns a fully-initialized SarekEnv (with system tray in keyring). Throws on failure.
std::unique_ptr<SarekEnv> run_bootstrap(const SarekConfig& cfg,
                                         const std::string& admin_password,
                                         const Tray& system_tray,
                                         uint8_t scrypt_n_log2 = 20);

// Interactive variant: prompts for system tray path/password and admin password
// (falling back to config file values where set), then calls run_bootstrap.
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
