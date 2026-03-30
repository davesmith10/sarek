#include "bootstrap/bootstrap.hpp"
#include "bootstrap/user_record.hpp"

#include <crystals/crystals.hpp>

#include <msgpack.hpp>
#include <yaml-cpp/yaml.h>

#include <unistd.h>

extern "C" {
#include "scrypt-kdf.h"
}

#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <array>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace sarek {

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

static std::array<uint8_t, 16> uuid_str_to_bytes(const std::string& s) {
    // Strip dashes from "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    std::string hex;
    hex.reserve(32);
    for (char c : s)
        if (c != '-') hex += c;

    if (hex.size() != 32)
        throw std::runtime_error("uuid_str_to_bytes: invalid UUID '" + s + "'");

    auto from_hex = [](char c) -> uint8_t {
        if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
        if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
        if (c >= 'A' && c <= 'F') return static_cast<uint8_t>(c - 'A' + 10);
        throw std::runtime_error("uuid_str_to_bytes: invalid hex character");
    };

    std::array<uint8_t, 16> out{};
    for (int i = 0; i < 16; ++i)
        out[i] = static_cast<uint8_t>((from_hex(hex[i*2]) << 4) | from_hex(hex[i*2+1]));
    return out;
}

// Serialise a Tray to YAML bytes for storage in BDB.
static std::vector<uint8_t> tray_to_yaml_bytes(const Tray& tray) {
    std::string s = emit_tray_yaml(tray);
    return {s.begin(), s.end()};
}

// Deserialise a Tray from YAML bytes as stored in BDB.
static Tray tray_from_yaml_bytes(const std::vector<uint8_t>& bytes) {
    char tmp[] = "/tmp/sarek-tray-XXXXXX";
    int fd = mkstemp(tmp);
    if (fd < 0) throw std::runtime_error("tray_from_yaml_bytes: mkstemp failed");
    if (write(fd, bytes.data(), bytes.size()) != static_cast<ssize_t>(bytes.size())) {
        close(fd); unlink(tmp);
        throw std::runtime_error("tray_from_yaml_bytes: write failed");
    }
    close(fd);
    try {
        Tray t = load_tray_yaml(tmp);
        unlink(tmp);
        return t;
    } catch (...) {
        unlink(tmp);
        throw;
    }
}

// Pack assertions as msgpack array of strings.
// NOTE: We write directly to tray_assertions DB rather than calling
// sarek::store_tray_assertions() to avoid a circular CMake dependency
// (sarek_bootstrap -> sarek_vault -> sarek_auth -> sarek_bootstrap).
// The msgpack format of pack_assertions AND the byte layout of
// uuid_str_to_bytes must stay in sync with vault.cpp::{pack_assertions,uuid_to_bytes}.
static std::vector<uint8_t> pack_assertions(const std::vector<std::string>& v) {
    msgpack::sbuffer buf;
    msgpack::packer<msgpack::sbuffer> pk(buf);
    pk.pack_array(static_cast<uint32_t>(v.size()));
    for (const auto& s : v) pk.pack(s);
    return {reinterpret_cast<const uint8_t*>(buf.data()),
            reinterpret_cast<const uint8_t*>(buf.data()) + buf.size()};
}

// Pack a tray DB record.
//   enc  0 = plain YAML tray bytes
//        1 = PWENC wire bytes
//   flags 0x01 = system tray
static std::vector<uint8_t> pack_tray_record(
        uint8_t enc, const std::string& alias,
        uint32_t flags, uint64_t owner,
        const std::vector<uint8_t>& blob) {
    msgpack::sbuffer buf;
    msgpack::packer<msgpack::sbuffer> pk(buf);

    pk.pack_map(5);
    pk.pack(std::string("enc")); pk.pack_uint8(enc);
    pk.pack(std::string("al"));  pk.pack(alias);
    pk.pack(std::string("fl"));  pk.pack_uint32(flags);
    pk.pack(std::string("ow"));  pk.pack_uint64(owner);
    pk.pack(std::string("bl"));
    pk.pack_bin(static_cast<uint32_t>(blob.size()));
    pk.pack_bin_body(reinterpret_cast<const char*>(blob.data()), blob.size());

    return {reinterpret_cast<const uint8_t*>(buf.data()),
            reinterpret_cast<const uint8_t*>(buf.data()) + buf.size()};
}

static void run_scrypt(const std::string& passwd,
                       const uint8_t* salt, size_t salt_len,
                       uint8_t n_log2, uint8_t r, uint8_t p,
                       uint8_t* out, size_t out_len) {
    uint64_t N = static_cast<uint64_t>(1) << n_log2;
    if (scrypt_kdf(reinterpret_cast<const uint8_t*>(passwd.data()), passwd.size(),
                   salt, salt_len, N, r, p, out, out_len) != 0)
        throw std::runtime_error("scrypt KDF failed");
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

std::vector<uint8_t> pwenc_decrypt_blob(const std::vector<uint8_t>& blob,
                                         const std::string& password) {
    PwBundle bundle = parse_pw_bundle(blob);
    int level = bundle.level;
    auto ksz = kyber_kem_sizes(level);

    // 1. scrypt(password, salt) → wrap_key
    uint8_t wrap_key[32];
    run_scrypt(password, bundle.salt, 32,
               bundle.scrypt_n_log2, bundle.scrypt_r, bundle.scrypt_p,
               wrap_key, 32);

    // 2. AES-256-GCM decrypt wrapped sk (no AAD)
    auto sk = aes256gcm_decrypt(wrap_key, bundle.wrap_nonce_tag_sk_enc);
    OPENSSL_cleanse(wrap_key, 32);
    if (sk.size() != ksz.sk_bytes)
        throw std::runtime_error("pwenc_decrypt_blob: unexpected sk size");

    // 3. Kyber decaps(sk, ct) → ss
    std::vector<uint8_t> ss(ksz.ss_bytes);
    int rc = 0;
    if      (level == 512)  rc = pqcrystals_kyber512_ref_dec(ss.data(), bundle.ct.data(), sk.data());
    else if (level == 768)  rc = pqcrystals_kyber768_ref_dec(ss.data(), bundle.ct.data(), sk.data());
    else                    rc = pqcrystals_kyber1024_ref_dec(ss.data(), bundle.ct.data(), sk.data());
    OPENSSL_cleanse(sk.data(), sk.size());
    if (rc != 0) throw std::runtime_error("pwenc_decrypt_blob: Kyber decaps failed");

    // 4. AES-256-GCM decrypt data (AAD = pw_bundle_aad)
    auto aad = pw_bundle_aad(level);
    auto plaintext = aes256gcm_decrypt_aad(ss.data(), bundle.data_nonce_tag_ct,
                                            aad.data(), aad.size());
    OPENSSL_cleanse(ss.data(), ss.size());
    return plaintext;
}

bool needs_bootstrap(const SarekConfig& cfg) {
    return !std::filesystem::exists(
        std::filesystem::path(cfg.db_path) / "__db.001");
}

std::string hash_password(const std::string& plaintext, uint8_t n_log2) {
    uint8_t salt[16];
    if (RAND_bytes(salt, 16) != 1)
        throw std::runtime_error("hash_password: RAND_bytes failed");

    uint8_t hash[32];
    constexpr uint8_t R = 8, P = 1;
    run_scrypt(plaintext, salt, 16, n_log2, R, P, hash, 32);

    std::string result =
        "scrypt$" + std::to_string(n_log2) + "$" +
        std::to_string(R) + "$" + std::to_string(P) + "$" +
        base64_encode(salt, 16) + "$" +
        base64_encode(hash, 32);

    OPENSSL_cleanse(hash, 32);
    return result;
}

bool verify_password(const std::string& plaintext, const std::string& stored) {
    // Parse "scrypt$N_log2$r$p$b64salt$b64hash"
    std::vector<std::string> parts;
    std::string tok;
    for (char c : stored) {
        if (c == '$') { parts.push_back(tok); tok.clear(); }
        else tok += c;
    }
    parts.push_back(tok);

    if (parts.size() != 6 || parts[0] != "scrypt")
        throw std::runtime_error("verify_password: unrecognised hash format");

    auto n_log2 = static_cast<uint8_t>(std::stoi(parts[1]));
    auto r      = static_cast<uint8_t>(std::stoi(parts[2]));
    auto p      = static_cast<uint8_t>(std::stoi(parts[3]));
    auto salt_bytes = base64_decode(parts[4]);
    auto hash_bytes = base64_decode(parts[5]);

    if (hash_bytes.size() != 32)
        throw std::runtime_error("verify_password: unexpected hash length");

    uint8_t computed[32];
    run_scrypt(plaintext, salt_bytes.data(), salt_bytes.size(),
               n_log2, r, p, computed, 32);

    bool match = (CRYPTO_memcmp(computed, hash_bytes.data(), 32) == 0);
    OPENSSL_cleanse(computed, 32);
    return match;
}

// ---------------------------------------------------------------------------
// import_system_tray / load_system_tray
// ---------------------------------------------------------------------------

Tray import_system_tray(const std::string& path,
                         const char* passwd, size_t passwd_len) {
    YAML::Node root;
    try {
        root = YAML::LoadFile(path);
    } catch (const YAML::Exception& e) {
        throw std::runtime_error(
            "import_system_tray: cannot load '" + path + "': " + e.what());
    }

    std::string type;
    if (root["type"]) type = root["type"].as<std::string>();

    if (type == "secure-tray") {
        SecureTray st = load_secure_tray_yaml(path);
        return unprotect_tray(st, passwd, passwd_len);
    } else {
        return load_tray_yaml(path);
    }
}

Tray load_system_tray(const SarekEnv& env) {
    auto bytes = env.get_system_tray_bytes();
    return tray_from_yaml_bytes(bytes);
}

// ---------------------------------------------------------------------------
// Internal helper: read the first non-empty line from a file
// ---------------------------------------------------------------------------

static std::string read_first_line(const std::string& path) {
    std::ifstream f(path);
    if (!f) throw std::runtime_error("cannot open file: " + path);
    std::string line;
    std::getline(f, line);
    if (!line.empty() && line.back() == '\r') line.pop_back();
    if (line.empty()) throw std::runtime_error("file is empty: " + path);
    return line;
}

// ---------------------------------------------------------------------------
// run_bootstrap
// ---------------------------------------------------------------------------

std::unique_ptr<SarekEnv> run_bootstrap(const SarekConfig& cfg,
                                         const std::string& admin_password,
                                         const Tray& system_tray,
                                         uint8_t scrypt_n_log2) {
    auto env = std::make_unique<SarekEnv>(cfg.db_path);
    auto txn = env->begin_txn();

    // ── system tray (imported, stored as plain YAML enc=0) ──────────────────
    auto sys_plain  = tray_to_yaml_bytes(system_tray);
    auto sys_id     = uuid_str_to_bytes(system_tray.id);
    auto sys_record = pack_tray_record(0, "system", 0x01, 0, sys_plain);

    env->tray().put(sys_id.data(), sys_id.size(),
                    sys_record.data(), sys_record.size(), txn.get());
    env->tray_alias().put("system",
        std::vector<uint8_t>(sys_id.begin(), sys_id.end()), txn.get());

    // ── system-token tray (Level2, plain YAML) ───────────────────────────────
    Tray token_tray = make_tray(TrayType::Level2, "system-token");
    auto tok_plain  = tray_to_yaml_bytes(token_tray);
    auto tok_id     = uuid_str_to_bytes(token_tray.id);
    auto tok_record = pack_tray_record(0, "system-token", 0x01, 0, tok_plain);

    env->tray().put(tok_id.data(), tok_id.size(),
                    tok_record.data(), tok_record.size(), txn.get());
    env->tray_alias().put("system-token",
        std::vector<uint8_t>(tok_id.begin(), tok_id.end()), txn.get());

    // ── admin user ────────────────────────────────────────────────────────────
    UserRecord admin;
    admin.user_id    = 1;
    admin.pwhash     = hash_password(admin_password, scrypt_n_log2);
    admin.flags      = kUserFlagAdmin;
    admin.assertions = {"usr:" + cfg.admin_user, "/*"};

    auto admin_bytes = pack_user_record(admin);
    env->user().put(cfg.admin_user, admin_bytes, txn.get());

    // Tray assertions: both system trays get "/*" (full admin scope)
    auto admin_ass = pack_assertions({"/*"});
    env->tray_assertions().put(sys_id.data(), sys_id.size(),
                               admin_ass.data(), admin_ass.size(), txn.get());
    env->tray_assertions().put(tok_id.data(), tok_id.size(),
                               admin_ass.data(), admin_ass.size(), txn.get());

    txn->commit();

    // ── Store system tray YAML bytes in kernel keyring ────────────────────────
    auto blob = KeyringBlob::store(
        "sarek:system-tray", sys_plain.data(), sys_plain.size());
    env->set_system_tray_keyring(std::move(blob));

    return env;
}

// ---------------------------------------------------------------------------
// run_bootstrap_interactive
// ---------------------------------------------------------------------------

std::unique_ptr<SarekEnv> run_bootstrap_interactive(const SarekConfig& cfg) {
    // ── Step 1: System tray path ──────────────────────────────────────────────
    std::string tray_path = cfg.system_tray_path;
    if (tray_path.empty()) {
        std::cout << "Please input path to the system tray: " << std::flush;
        std::getline(std::cin, tray_path);
        if (tray_path.empty())
            throw std::runtime_error("No system tray path provided");
    }

    // ── Step 2: Peek at YAML type field ──────────────────────────────────────
    YAML::Node root;
    try {
        root = YAML::LoadFile(tray_path);
    } catch (const YAML::Exception& e) {
        throw std::runtime_error(
            "run_bootstrap_interactive: cannot load tray file '" +
            tray_path + "': " + e.what());
    }
    std::string type;
    if (root["type"]) type = root["type"].as<std::string>();

    // ── Step 3: Tray password (only for secure-tray) ─────────────────────────
    char tray_pw_buf[256] = {};
    std::string tray_pw_str;  // holds password if read from file
    const char* tray_pw  = nullptr;
    size_t      tray_pwl = 0;

    if (type == "secure-tray") {
        if (!cfg.system_tray_password_file.empty()) {
            tray_pw_str = read_first_line(cfg.system_tray_password_file);
            tray_pw  = tray_pw_str.c_str();
            tray_pwl = tray_pw_str.size();
        } else {
            if (EVP_read_pw_string(tray_pw_buf, sizeof(tray_pw_buf),
                                   "Tray is protected. Please provide the password: ", 0) != 0)
                throw std::runtime_error("Tray password input failed");
            tray_pw  = tray_pw_buf;
            tray_pwl = std::strlen(tray_pw_buf);
        }
    }

    Tray system_tray = import_system_tray(tray_path, tray_pw, tray_pwl);
    OPENSSL_cleanse(tray_pw_buf, sizeof(tray_pw_buf));

    // ── Step 4: Admin password ────────────────────────────────────────────────
    std::string admin_pw;
    if (!cfg.user_password_file.empty()) {
        admin_pw = read_first_line(cfg.user_password_file);
    } else {
        char passwd[256] = {};
        char verify[256] = {};

        if (EVP_read_pw_string(passwd, sizeof(passwd), "Admin password: ", 0) != 0)
            throw std::runtime_error("Password input failed");

        if (EVP_read_pw_string(verify, sizeof(verify), "Confirm password: ", 0) != 0) {
            OPENSSL_cleanse(passwd, sizeof(passwd));
            throw std::runtime_error("Password input failed");
        }

        if (std::strcmp(passwd, verify) != 0) {
            OPENSSL_cleanse(passwd, sizeof(passwd));
            OPENSSL_cleanse(verify, sizeof(verify));
            throw std::runtime_error("Passwords do not match");
        }
        OPENSSL_cleanse(verify, sizeof(verify));
        admin_pw = passwd;
        OPENSSL_cleanse(passwd, sizeof(passwd));
    }

    return run_bootstrap(cfg, admin_pw, system_tray);
}

} // namespace sarek
