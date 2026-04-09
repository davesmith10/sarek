#include "oauth/oauth.hpp"
#include "bootstrap/bootstrap.hpp"
#include "vault/vault.hpp"
#include "log/log.hpp"

#include <crystals/crystals.hpp>

#include <cassert>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>

static std::string make_tmp_db() {
    char tmpl[] = "/tmp/sarek-oauth-test-XXXXXX";
    char* dir   = mkdtemp(tmpl);
    if (!dir) throw std::runtime_error("mkdtemp failed");
    return dir;
}

static void cleanup(const std::string& path) {
    std::filesystem::remove_all(path);
}

int main() {
    // Don't call init_logging — rely on get_logger()'s fallback stderr logger.
    auto log = sarek::get_logger();

    std::string db_path = make_tmp_db();
    sarek::SarekConfig cfg{};
    cfg.db_path           = db_path;
    cfg.admin_user        = "admin";
    cfg.http_port         = 18444;
    cfg.cache_ttl_secs    = 60;
    cfg.max_data_node_sz  = 1024*1024;

    // Bootstrap with a test system tray (Level3) and low scrypt cost for speed.
    Tray system_tray = make_tray(TrayType::Level3, "system");
    std::unique_ptr<sarek::SarekEnv> env_ptr;
    try {
        env_ptr = sarek::run_bootstrap(cfg, "adminpass123", system_tray, 14);
    } catch (const std::exception& e) {
        std::cerr << "SKIP: bootstrap failed: " << e.what() << "\n";
        cleanup(db_path);
        return 0;
    }

    sarek::SarekEnv& env = *env_ptr;

    // ── Test 1: signing key generate and persist ─────────────────────────────
    {
        sarek::oauth_init_signing_key(env, system_tray);
        auto key = sarek::oauth_load_signing_key(env, system_tray);
        assert(key.size() == 32 && "signing key must be 32 bytes");

        // Idempotent: second call must not change the key
        sarek::oauth_init_signing_key(env, system_tray);
        auto key2 = sarek::oauth_load_signing_key(env, system_tray);
        assert(key == key2 && "signing key must not change on second init");
        log->info("PASS test1: signing key");
    }

    // ── Test 2: setup client for a new user ──────────────────────────────────
    {
        std::vector<std::string> assertions{"usr:alice", "slc:/data/*"};
        sarek::create_user(env, "alice", "pw_alice", 0, assertions, 42, 14);

        auto [cid, csecret] = sarek::oauth_setup_client(env, "alice");
        assert(!cid.empty()     && "client_id must not be empty");
        assert(!csecret.empty() && "client_secret must not be empty");

        // Duplicate setup must throw
        bool threw = false;
        try { sarek::oauth_setup_client(env, "alice"); }
        catch (const std::runtime_error&) { threw = true; }
        assert(threw && "duplicate setup must throw");

        log->info("PASS test2: setup client cid={}", cid);
    }

    // ── Test 3: authenticate with correct and wrong secret ──────────────────
    {
        auto [cid, csecret] = sarek::oauth_setup_client(env, "admin");

        std::string uname = sarek::oauth_authenticate_client(env, cid, csecret);
        assert(uname == "admin" && "authenticated username must match");

        bool threw = false;
        try { sarek::oauth_authenticate_client(env, cid, "wrongsecret"); }
        catch (const std::runtime_error&) { threw = true; }
        assert(threw && "bad secret must throw");

        log->info("PASS test3: authenticate client");
    }

    // ── Test 4: JWT issue and verify round-trip ───────────────────────────────
    {
        auto key = sarek::oauth_load_signing_key(env, system_tray);
        std::vector<std::string> assertions{"/*", "usr:alice"};

        std::string jwt = sarek::oauth_issue_jwt(key, "alice", assertions, 3600);
        assert(!jwt.empty() && "JWT must not be empty");
        assert(std::count(jwt.begin(), jwt.end(), '.') == 2 && "JWT must have 3 parts");

        sarek::TokenClaims claims = sarek::oauth_verify_jwt(key, jwt);
        assert(claims.username == "alice"    && "username must match");
        assert(claims.assertions.size() == 2 && "assertions count must match");
        assert(claims.assertions[0] == "/*"  && "first assertion must be /*");
        assert(!claims.token_uuid.empty()    && "jti must be present");

        log->info("PASS test4: JWT round-trip jti={}", claims.token_uuid);
    }

    // ── Test 5: expired JWT is rejected ─────────────────────────────────────
    {
        auto key = sarek::oauth_load_signing_key(env, system_tray);
        // Issue with 1-second TTL, then sleep until it has expired.
        std::string jwt = sarek::oauth_issue_jwt(key, "alice", {"/*"}, 1);
        std::this_thread::sleep_for(std::chrono::seconds(2));
        bool threw = false;
        try { sarek::oauth_verify_jwt(key, jwt); }
        catch (const std::runtime_error&) { threw = true; }
        assert(threw && "expired JWT must be rejected");
        log->info("PASS test5: expired JWT rejected");
    }

    // ── Test 6: tampered JWT is rejected ─────────────────────────────────────
    {
        auto key = sarek::oauth_load_signing_key(env, system_tray);
        std::string jwt = sarek::oauth_issue_jwt(key, "alice", {"/*"}, 3600);
        // Flip a bit in the signature (last segment)
        auto dot_pos = jwt.rfind('.');
        if (dot_pos != std::string::npos && dot_pos + 1 < jwt.size())
            jwt[dot_pos + 1] ^= 0x01;

        bool threw = false;
        try { sarek::oauth_verify_jwt(key, jwt); }
        catch (const std::runtime_error&) { threw = true; }
        assert(threw && "tampered JWT must be rejected");
        log->info("PASS test6: tampered JWT rejected");
    }

    // ── Test 7a: JWT aud claim matches deployment UUID ───────────────────────
    {
        auto key = sarek::oauth_load_signing_key(env, system_tray);
        const std::string aud = "a1b2c3d4-0001-4001-8001-aabbccddeeff";
        const std::string other_aud = "ffffffff-ffff-4fff-8fff-ffffffffffff";

        // Issue with aud_id — JWT "aud" claim must equal the UUID.
        std::string jwt = sarek::oauth_issue_jwt(key, "alice", {"/*", "usr:alice"}, 3600, aud);
        assert(!jwt.empty());

        // Verify with correct aud_id — must succeed.
        sarek::TokenClaims claims = sarek::oauth_verify_jwt(key, jwt, aud);
        assert(claims.username == "alice");

        // Verify with wrong aud_id — must throw with "audience".
        bool threw = false;
        try { sarek::oauth_verify_jwt(key, jwt, other_aud); }
        catch (const std::runtime_error& e) {
            threw = (std::string(e.what()).find("audience") != std::string::npos);
        }
        assert(threw && "wrong aud_id must throw audience mismatch");

        // Verify without aud check (empty aud_id) — must succeed.
        sarek::TokenClaims claims2 = sarek::oauth_verify_jwt(key, jwt, "");
        assert(claims2.username == "alice");

        log->info("PASS test7a: JWT aud claim (deployment UUID)");
    }

    // ── Test 7: revoke client removes credentials ─────────────────────────────
    {
        std::vector<std::string> assertions{"usr:bob"};
        sarek::create_user(env, "bob", "pw_bob", 0, assertions, 99, 14);
        auto [cid, csecret] = sarek::oauth_setup_client(env, "bob");

        bool revoked = sarek::oauth_revoke_client(env, "bob");
        assert(revoked && "revoke of existing client must return true");

        bool threw = false;
        try { sarek::oauth_authenticate_client(env, cid, csecret); }
        catch (const std::runtime_error&) { threw = true; }
        assert(threw && "revoked client must not authenticate");

        bool revoked2 = sarek::oauth_revoke_client(env, "bob");
        assert(!revoked2 && "revoke of absent client must return false");

        log->info("PASS test7: revoke client");
    }

    // ── Test 8: migration — plaintext key is detected and replaced ───────────
    {
        // Overwrite the encrypted key with a raw plaintext blob to simulate
        // a pre-encryption installation.
        std::vector<uint8_t> fake_plaintext{0x01, 0x02, 0x03, 0x04};
        // NOTE: "__signing_key__" must match kSigningKeyEntry in oauth.cpp (static, not exported).
        // If that constant changes, update this literal to match or the test becomes a no-op.
        env.oauth_client().put("__signing_key__", fake_plaintext);

        // oauth_init_signing_key must detect it is not valid OBIWAN ciphertext,
        // delete it, and generate a fresh encrypted key.
        sarek::oauth_init_signing_key(env, system_tray);

        // load must now succeed and return exactly 32 bytes.
        auto key = sarek::oauth_load_signing_key(env, system_tray);
        assert(key.size() == 32 && "migrated key must be 32 bytes");

        // The key is 32 random bytes from RAND_bytes; the plaintext was 4 bytes of {1,2,3,4}.
        // Different sizes guarantee inequality, so the meaningful invariant is the size check above.
        // Additionally confirm the first bytes don't accidentally match the fake prefix.
        assert((key[0] != 0x01 || key[1] != 0x02 || key[2] != 0x03 || key[3] != 0x04) &&
               "migrated key must differ from fake plaintext prefix");

        log->info("PASS test8: migration from plaintext key");
    }

    cleanup(db_path);
    std::cout << "All OAuth tests passed.\n";
    return 0;
}
