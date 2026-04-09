#include "auth/auth.hpp"
#include "bootstrap/user_record.hpp"

#include <crystals/crystals.hpp>

#include <msgpack.hpp>

#include <openssl/rand.h>

#include <cstdio>
#include <unistd.h>
#include <cstring>
#include <ctime>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace sarek {

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// Find the ECDSA P-256 slot in a tray; throws if absent.
static const Slot& require_ecdsa_p256_slot(const Tray& tray, bool need_sk) {
    for (const auto& s : tray.slots) {
        if (s.alg_name == "ECDSA P-256") {
            if (need_sk && s.sk.empty())
                throw std::runtime_error(
                    "issue_token: ECDSA P-256 slot has no secret key "
                    "(is this a public-only tray?)");
            return s;
        }
    }
    throw std::runtime_error("issue_token: tray has no ECDSA P-256 slot");
}

// Join a vector of strings with '\n'.
static std::string join_assertions(const std::vector<std::string>& v) {
    std::string out;
    for (size_t i = 0; i < v.size(); ++i) {
        if (i) out += '\n';
        out += v[i];
    }
    return out;
}

// Split a string on '\n'.
static std::vector<std::string> split_assertions(const std::string& s) {
    std::vector<std::string> out;
    std::istringstream ss(s);
    std::string line;
    while (std::getline(ss, line))
        if (!line.empty()) out.push_back(line);
    return out;
}

// Generate a random UUID v4 into a 16-byte buffer.
static void gen_uuid_v4(uint8_t out[16]) {
    if (RAND_bytes(out, 16) != 1)
        throw std::runtime_error("gen_uuid_v4: RAND_bytes failed");
    out[6] = (out[6] & 0x0f) | 0x40;  // version 4
    out[8] = (out[8] & 0x3f) | 0x80;  // variant 10xx
}

// Format 16 raw UUID bytes as "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx".
static std::string format_uuid(const uint8_t uuid[16]) {
    char buf[37];
    std::snprintf(buf, sizeof(buf),
        "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        uuid[0],  uuid[1],  uuid[2],  uuid[3],
        uuid[4],  uuid[5],  uuid[6],  uuid[7],
        uuid[8],  uuid[9],  uuid[10], uuid[11],
        uuid[12], uuid[13], uuid[14], uuid[15]);
    return buf;
}

// Parse the outer msgpack tray-DB record and return the inner blob + enc byte.
static std::vector<uint8_t> parse_tray_record_blob(
        const std::vector<uint8_t>& record, uint8_t& enc_out) {
    msgpack::object_handle oh = msgpack::unpack(
        reinterpret_cast<const char*>(record.data()), record.size());
    const msgpack::object& obj = oh.get();

    if (obj.type != msgpack::type::MAP)
        throw std::runtime_error("parse_tray_record_blob: expected map");

    std::vector<uint8_t> blob;
    bool got_enc = false, got_blob = false;
    const auto& map = obj.via.map;

    for (uint32_t i = 0; i < map.size; ++i) {
        const auto& kv = map.ptr[i];
        if (kv.key.type != msgpack::type::STR) continue;
        std::string key{kv.key.via.str.ptr, kv.key.via.str.size};

        if (key == "enc") {
            if (kv.val.type != msgpack::type::POSITIVE_INTEGER)
                throw std::runtime_error("parse_tray_record_blob: 'enc' must be uint");
            enc_out = static_cast<uint8_t>(kv.val.via.u64);
            got_enc = true;
        } else if (key == "bl") {
            if (kv.val.type != msgpack::type::BIN)
                throw std::runtime_error("parse_tray_record_blob: 'bl' must be bin");
            blob.assign(
                reinterpret_cast<const uint8_t*>(kv.val.via.bin.ptr),
                reinterpret_cast<const uint8_t*>(kv.val.via.bin.ptr) + kv.val.via.bin.size);
            got_blob = true;
        }
    }

    if (!got_enc || !got_blob)
        throw std::runtime_error("parse_tray_record_blob: missing 'enc' or 'bl' fields");

    return blob;
}

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

// ---------------------------------------------------------------------------
// issue_token
// ---------------------------------------------------------------------------

std::vector<uint8_t> issue_token(const UserRecord& user,
                                  const Tray& system_token_tray,
                                  int64_t ttl_secs,
                                  const std::string& aud_id) {
    const Slot& sig_slot = require_ecdsa_p256_slot(system_token_tray, /*need_sk=*/true);

    // Build the assertion payload.  Prepend aud:<uuid> when a deployment ID is set
    // so tokens from one installation cannot be replayed against another.
    std::string data_str = join_assertions(user.assertions);
    if (!aud_id.empty()) {
        std::string aud_assertion = "aud:" + aud_id;
        data_str = data_str.empty()
            ? aud_assertion
            : data_str + "\n" + aud_assertion;
    }
    if (data_str.empty() || data_str.size() > 256)
        throw std::runtime_error(
            "issue_token: assertions encode to " + std::to_string(data_str.size()) +
            " bytes; must be 1–256");

    Token tok;
    tok.data.assign(data_str.begin(), data_str.end());
    tok.issued_at  = static_cast<int64_t>(std::time(nullptr));
    tok.expires_at = tok.issued_at + ttl_secs;
    tok.algorithm  = kTokenAlgECDSAP256;
    parse_uuid(system_token_tray.id, tok.tray_uuid);
    gen_uuid_v4(tok.token_uuid);

    auto canonical = token_canonical_bytes(tok);
    ec_sig::sign("ECDSA P-256", sig_slot.sk, canonical, tok.signature);

    return token_pack(tok);
}

// ---------------------------------------------------------------------------
// validate_token
// ---------------------------------------------------------------------------

TokenClaims validate_token(const std::vector<uint8_t>& wire,
                            const Tray& system_token_tray_pub,
                            const std::string& aud_id) {
    Token tok = token_unpack(wire);

    // Time bounds
    int64_t now = static_cast<int64_t>(std::time(nullptr));
    if (now < tok.issued_at)
        throw std::runtime_error("validate_token: token is not yet valid");
    if (now >= tok.expires_at)
        throw std::runtime_error("validate_token: token has expired");

    // Tray UUID must match
    uint8_t expected[16];
    parse_uuid(system_token_tray_pub.id, expected);
    if (std::memcmp(tok.tray_uuid, expected, 16) != 0)
        throw std::runtime_error("validate_token: tray UUID mismatch");

    // Signature
    const Slot& sig_slot = require_ecdsa_p256_slot(system_token_tray_pub, /*need_sk=*/false);
    auto canonical = token_canonical_bytes(tok);
    if (!ec_sig::verify("ECDSA P-256", sig_slot.pk, canonical, tok.signature))
        throw std::runtime_error("validate_token: invalid signature");

    // Parse assertions
    std::string data_str(tok.data.begin(), tok.data.end());
    auto assertions = split_assertions(data_str);

    // Extract username from "usr:<name>" assertion
    std::string username;
    for (const auto& a : assertions) {
        if (a.substr(0, 4) == "usr:") {
            username = a.substr(4);
            break;
        }
    }
    if (username.empty())
        throw std::runtime_error("validate_token: no 'usr:' assertion found in token data");

    // Audience check: if the server has a deployment ID, the token must carry it.
    if (!aud_id.empty()) {
        const std::string expected = "aud:" + aud_id;
        bool found = false;
        for (const auto& a : assertions) {
            if (a == expected) { found = true; break; }
        }
        if (!found)
            throw std::runtime_error("validate_token: audience mismatch");
    }

    return {username, assertions, format_uuid(tok.token_uuid)};
}

// ---------------------------------------------------------------------------
// load_tray_by_alias
// ---------------------------------------------------------------------------

Tray load_tray_by_alias(SarekEnv& env, const std::string& alias) {
    auto id_bytes = env.tray_alias().get(alias);
    if (!id_bytes)
        throw std::runtime_error("load_tray_by_alias: alias '" + alias + "' not found");
    if (id_bytes->size() != 16)
        throw std::runtime_error("load_tray_by_alias: alias value is not 16 bytes");

    auto record_bytes = env.tray().get(id_bytes->data(), id_bytes->size());
    if (!record_bytes)
        throw std::runtime_error("load_tray_by_alias: tray record for alias '" + alias + "' not found");

    uint8_t enc = 0;
    auto blob = parse_tray_record_blob(*record_bytes, enc);

    if (enc != 0)
        throw std::runtime_error(
            "load_tray_by_alias: tray '" + alias + "' is password-encrypted; "
            "cannot load without password");

    return tray_from_yaml_bytes(blob);
}

bool is_tray_encrypted(SarekEnv& env, const std::string& alias) {
    auto id_bytes = env.tray_alias().get(alias);
    if (!id_bytes || id_bytes->size() != 16) return false;
    auto record_bytes = env.tray().get(id_bytes->data(), id_bytes->size());
    if (!record_bytes) return false;
    uint8_t enc = 0;
    parse_tray_record_blob(*record_bytes, enc);
    return enc != 0;
}

Tray load_tray_by_alias_pwenc(SarekEnv& env, const std::string& alias,
                               const std::string& password) {
    auto id_bytes = env.tray_alias().get(alias);
    if (!id_bytes)
        throw std::runtime_error("load_tray_by_alias_pwenc: alias '" + alias + "' not found");
    if (id_bytes->size() != 16)
        throw std::runtime_error("load_tray_by_alias_pwenc: alias value is not 16 bytes");

    auto record_bytes = env.tray().get(id_bytes->data(), id_bytes->size());
    if (!record_bytes)
        throw std::runtime_error("load_tray_by_alias_pwenc: tray record not found");

    uint8_t enc = 0;
    auto blob = parse_tray_record_blob(*record_bytes, enc);
    if (enc == 0)
        throw std::runtime_error("load_tray_by_alias_pwenc: tray '" + alias + "' is not password-encrypted");

    auto plain = pwenc_decrypt_blob(blob, password);
    return tray_from_yaml_bytes(plain);
}

// ---------------------------------------------------------------------------
// load_user
// ---------------------------------------------------------------------------

std::optional<UserRecord> load_user(SarekEnv& env, const std::string& username) {
    auto bytes = env.user().get(username);
    if (!bytes) return std::nullopt;
    return unpack_user_record(*bytes);
}

// ---------------------------------------------------------------------------
// authenticate_user
// ---------------------------------------------------------------------------

std::optional<UserRecord> authenticate_user(SarekEnv& env,
                                             const std::string& username,
                                             const std::string& password) {
    auto opt = load_user(env, username);
    if (!opt)
        throw std::runtime_error("authenticate_user: user '" + username + "' not found");

    const UserRecord& user = *opt;

    if (user.flags & kUserFlagLocked)
        throw std::runtime_error("authenticate_user: user '" + username + "' is locked");

    // "none" sentinel means no password was ever set (invite-only account)
    if (user.pwhash == "none")
        return std::nullopt;

    if (!verify_password(password, user.pwhash))
        return std::nullopt;

    return user;
}

} // namespace sarek
