#include "oauth/oauth.hpp"
#include "bootstrap/bootstrap.hpp"   // hash_password, verify_password
#include "auth/auth.hpp"             // load_user, TokenClaims
#include "vault/vault.hpp"           // obiwan_encrypt, obiwan_decrypt
#include "log/log.hpp"

extern "C" {
#include <oauth2/log.h>
#include <oauth2/jose.h>
#include <cjose/cjose.h>
#include <jansson.h>
}

#include <crystals/crystals.hpp>     // base64_encode
#include <openssl/rand.h>
#include <msgpack.hpp>

#include <cstdio>
#include <cstring>
#include <ctime>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

namespace sarek {

// ---------------------------------------------------------------------------
// liboauth2 log — WARN level to stderr (suppresses info/debug noise)
// ---------------------------------------------------------------------------
static oauth2_log_t* get_oauth2_log() {
    static oauth2_log_t* log =
        oauth2_log_init(OAUTH2_LOG_WARN, &oauth2_log_sink_stderr);
    return log;
}

// ---------------------------------------------------------------------------
// Signing key management
// ---------------------------------------------------------------------------

static const std::string kSigningKeyEntry{"__signing_key__"};

void oauth_init_signing_key(SarekEnv& env, const Tray& system_tray) {
    auto existing = env.oauth_client().get(kSigningKeyEntry);
    if (existing) {
        // Check for OBIWAN magic prefix to distinguish encrypted from plaintext.
        static const uint8_t kObiwan[] = {'O','B','I','W','A','N','0','1'};
        const bool looks_encrypted = existing->size() >= 8 &&
            std::memcmp(existing->data(), kObiwan, 8) == 0;
        if (looks_encrypted) {
            obiwan_decrypt(*existing, system_tray);  // throws on real crypto failure
            return;  // already encrypted — idempotent
        }
        // Stored bytes do not start with OBIWAN magic — legacy plaintext key.
        env.oauth_client().del(kSigningKeyEntry);
        get_logger()->warn("oauth.signing_key: replaced plaintext key (JWTs invalidated)");
    }

    std::vector<uint8_t> key(32);
    if (RAND_bytes(key.data(), 32) != 1)
        throw std::runtime_error("oauth_init_signing_key: RAND_bytes failed");

    auto ciphertext = obiwan_encrypt(key, system_tray);
    OPENSSL_cleanse(key.data(), key.size());
    env.oauth_client().put(kSigningKeyEntry, ciphertext);
    get_logger()->info("oauth.signing_key: generated");
}

std::vector<uint8_t> oauth_load_signing_key(SarekEnv& env, const Tray& system_tray) {
    auto val = env.oauth_client().get(kSigningKeyEntry);
    if (!val)
        throw std::runtime_error("OAuth signing key not found; run bootstrap first");
    return obiwan_decrypt(*val, system_tray);
}

// ---------------------------------------------------------------------------
// Client record serialization (msgpack)
// Keys: "un"=username, "ci"=client_id, "sh"=secret_hash, "cr"=created
// ---------------------------------------------------------------------------

static std::vector<uint8_t> pack_oauth_client(
    const OAuthClientRecord& r, const std::string& secret_hash)
{
    msgpack::sbuffer buf;
    msgpack::packer<msgpack::sbuffer> pk(buf);
    pk.pack_map(4);
    pk.pack(std::string("un")); pk.pack(r.username);
    pk.pack(std::string("ci")); pk.pack(r.client_id);
    pk.pack(std::string("sh")); pk.pack(secret_hash);
    pk.pack(std::string("cr")); pk.pack(r.created);
    return {reinterpret_cast<const uint8_t*>(buf.data()),
            reinterpret_cast<const uint8_t*>(buf.data()) + buf.size()};
}

struct OAuthClientData {
    OAuthClientRecord rec;
    std::string       secret_hash;
};

static OAuthClientData unpack_oauth_client(const std::vector<uint8_t>& data) {
    auto oh  = msgpack::unpack(reinterpret_cast<const char*>(data.data()), data.size());
    auto mp  = oh.get().as<std::map<std::string, msgpack::object>>();
    OAuthClientData d;
    d.rec.username  = mp.at("un").as<std::string>();
    d.rec.client_id = mp.at("ci").as<std::string>();
    d.secret_hash   = mp.at("sh").as<std::string>();
    d.rec.created   = mp.at("cr").as<int64_t>();
    return d;
}

// ---------------------------------------------------------------------------
// Client CRUD
// ---------------------------------------------------------------------------

static const std::string kUserPrefix{"user:"};

std::pair<std::string,std::string> oauth_setup_client(
    SarekEnv& env, const std::string& username)
{
    auto user_opt = load_user(env, username);
    if (!user_opt)
        throw std::runtime_error("user not found: " + username);

    std::string user_key = kUserPrefix + username;
    if (env.oauth_client().get(user_key))
        throw std::runtime_error(
            "OAuth client already exists for '" + username + "'; revoke first");

    // Generate client_id: 32 lowercase hex chars from 16 random bytes
    uint8_t id_bytes[16];
    if (RAND_bytes(id_bytes, 16) != 1)
        throw std::runtime_error("RAND_bytes failed");
    char id_buf[33];
    for (int i = 0; i < 16; i++)
        std::snprintf(id_buf + i*2, 3, "%02x", id_bytes[i]);
    std::string client_id(id_buf, 32);

    // Generate client_secret: 32 random bytes, base64-encoded
    uint8_t secret_bytes[32];
    if (RAND_bytes(secret_bytes, 32) != 1)
        throw std::runtime_error("RAND_bytes failed");
    std::string client_secret =
        base64_encode(secret_bytes, sizeof(secret_bytes));

    std::string secret_hash = hash_password(client_secret);

    OAuthClientRecord rec{username, client_id,
                          static_cast<int64_t>(std::time(nullptr))};
    auto packed = pack_oauth_client(rec, secret_hash);

    auto txn = env.begin_txn();
    env.oauth_client().put(user_key, packed, txn.get());
    env.oauth_client().put(client_id, packed, txn.get());
    txn->commit();

    get_logger()->info("oauth.setup: username={} client_id={}", username, client_id);
    return {client_id, client_secret};
}

bool oauth_revoke_client(SarekEnv& env, const std::string& username) {
    std::string user_key = kUserPrefix + username;
    auto val = env.oauth_client().get(user_key);
    if (!val) return false;

    auto cd  = unpack_oauth_client(*val);
    auto txn = env.begin_txn();
    env.oauth_client().del(user_key,         txn.get());
    env.oauth_client().del(cd.rec.client_id, txn.get());
    txn->commit();

    get_logger()->info("oauth.revoke: username={} client_id={}",
                       username, cd.rec.client_id);
    return true;
}

std::string oauth_authenticate_client(SarekEnv& env,
    const std::string& client_id, const std::string& client_secret)
{
    auto val = env.oauth_client().get(client_id);
    if (!val)
        throw std::runtime_error("invalid_client");

    auto cd = unpack_oauth_client(*val);
    if (!verify_password(client_secret, cd.secret_hash))
        throw std::runtime_error("invalid_client");

    return cd.rec.username;
}

// ---------------------------------------------------------------------------
// JWT issue (liboauth2 oauth2_jwt_create + cjose oct JWK)
// ---------------------------------------------------------------------------

std::string oauth_issue_jwt(
    const std::vector<uint8_t>& signing_key,
    const std::string& username,
    const std::vector<std::string>& assertions,
    int64_t ttl_secs,
    const std::string& aud_id)
{
    cjose_err err{};
    cjose_jwk_t* jwk = cjose_jwk_create_oct_spec(
        signing_key.data(), signing_key.size(), &err);
    if (!jwk)
        throw std::runtime_error(
            std::string("cjose_jwk_create_oct_spec: ") + (err.message ? err.message : "?"));

    // Build extra claims: "asr" array holds all SAREK assertions verbatim
    json_t* extra   = json_object();
    json_t* asr_arr = json_array();
    for (const auto& a : assertions)
        json_array_append_new(asr_arr, json_string(a.c_str()));
    json_object_set_new(extra, "asr", asr_arr);

    // NOTE: oauth2_jwt_create adds oauth2_time_now_sec() internally, so pass duration only.
    auto exp = static_cast<oauth2_uint_t>(ttl_secs > 0 ? ttl_secs : 0);

    char* jwt_str = oauth2_jwt_create(
        get_oauth2_log(),
        jwk,
        "HS256",
        "sarek",            // iss
        username.c_str(),   // sub
        nullptr,            // client_id claim (unused)
        aud_id.empty() ? "sarek" : aud_id.c_str(),  // aud
        exp,
        true,               // include iat
        true,               // include jti
        extra
    );

    json_decref(extra);
    cjose_jwk_release(jwk);

    if (!jwt_str)
        throw std::runtime_error("oauth2_jwt_create returned null");

    std::string result(jwt_str);
    std::free(jwt_str);
    return result;
}

// ---------------------------------------------------------------------------
// JWT verify (cjose directly — no liboauth2 needed for verification)
// ---------------------------------------------------------------------------

TokenClaims oauth_verify_jwt(
    const std::vector<uint8_t>& signing_key,
    const std::string& jwt_str,
    const std::string& aud_id)
{
    cjose_err err{};

    // Import compact serialization
    cjose_jws_t* jws = cjose_jws_import(jwt_str.c_str(), jwt_str.size(), &err);
    if (!jws)
        throw std::runtime_error(
            std::string("JWT import failed: ") + (err.message ? err.message : "?"));

    // Build verification key
    cjose_jwk_t* jwk = cjose_jwk_create_oct_spec(
        signing_key.data(), signing_key.size(), &err);
    if (!jwk) {
        cjose_jws_release(jws);
        throw std::runtime_error(
            std::string("cjose_jwk_create_oct_spec: ") + (err.message ? err.message : "?"));
    }

    // Verify signature
    if (!cjose_jws_verify(jws, jwk, &err)) {
        cjose_jwk_release(jwk);
        cjose_jws_release(jws);
        throw std::runtime_error("JWT signature verification failed");
    }
    cjose_jwk_release(jwk);

    // Extract plaintext payload (raw JSON bytes)
    uint8_t* payload_data = nullptr;
    size_t   payload_len  = 0;
    if (!cjose_jws_get_plaintext(jws, &payload_data, &payload_len, &err)) {
        cjose_jws_release(jws);
        throw std::runtime_error("JWT plaintext extraction failed");
    }

    // Parse JSON payload
    json_error_t jerr{};
    json_t* claims_j = json_loadb(
        reinterpret_cast<const char*>(payload_data),
        payload_len, 0, &jerr);
    cjose_jws_release(jws);   // payload_data owned by jws; release after json_loadb

    if (!claims_j)
        throw std::runtime_error(
            std::string("JWT payload JSON parse error: ") + jerr.text);

    // Check exp
    json_t* exp_j = json_object_get(claims_j, "exp");
    if (!exp_j || !json_is_integer(exp_j)) {
        json_decref(claims_j);
        throw std::runtime_error("JWT missing exp claim");
    }
    if (json_integer_value(exp_j) < static_cast<json_int_t>(std::time(nullptr))) {
        json_decref(claims_j);
        throw std::runtime_error("JWT has expired");
    }

    // Check aud when a deployment ID is configured
    if (!aud_id.empty()) {
        json_t* aud_j = json_object_get(claims_j, "aud");
        bool match = false;
        if (aud_j && json_is_string(aud_j)) {
            match = (aud_id == json_string_value(aud_j));
        } else if (aud_j && json_is_array(aud_j)) {
            size_t idx; json_t* item;
            json_array_foreach(aud_j, idx, item) {
                if (json_is_string(item) && aud_id == json_string_value(item)) {
                    match = true; break;
                }
            }
        }
        if (!match) {
            json_decref(claims_j);
            throw std::runtime_error("JWT audience mismatch");
        }
    }

    // Extract sub
    json_t* sub_j = json_object_get(claims_j, "sub");
    if (!sub_j || !json_is_string(sub_j)) {
        json_decref(claims_j);
        throw std::runtime_error("JWT missing sub claim");
    }
    std::string username = json_string_value(sub_j);

    // Extract jti (optional)
    std::string jti;
    json_t* jti_j = json_object_get(claims_j, "jti");
    if (jti_j && json_is_string(jti_j))
        jti = json_string_value(jti_j);

    // Extract assertions from "asr" array
    std::vector<std::string> assertions;
    json_t* asr_j = json_object_get(claims_j, "asr");
    if (asr_j && json_is_array(asr_j)) {
        size_t  idx;
        json_t* item;
        json_array_foreach(asr_j, idx, item) {
            if (json_is_string(item))
                assertions.emplace_back(json_string_value(item));
        }
    }

    json_decref(claims_j);

    TokenClaims c;
    c.username   = username;
    c.assertions = std::move(assertions);
    c.token_uuid = jti;
    return c;
}

} // namespace sarek
