#include "bootstrap/bootstrap.hpp"
#include "bootstrap/user_record.hpp"

#include <crystals/tray.hpp>

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <vector>

namespace fs = std::filesystem;

static std::string make_tmpdir() {
    return "/tmp/sarek_bootstrap_test_" + std::to_string(std::rand());
}

// ---------------------------------------------------------------------------
static void test_hash_verify() {
    // Use n_log2=14 (very fast) for test speed.
    std::string h = sarek::hash_password("hunter2", 14);
    assert(!h.empty());
    assert(h.substr(0, 7) == "scrypt$");
    assert(sarek::verify_password("hunter2", h));
    assert(!sarek::verify_password("wrongpass", h));

    // Two hashes of the same password differ (random salt).
    std::string h2 = sarek::hash_password("hunter2", 14);
    assert(h != h2);
    assert(sarek::verify_password("hunter2", h2));

    std::puts("hash/verify password: OK");
}

static void test_user_record_roundtrip() {
    sarek::UserRecord r;
    r.user_id    = 42;
    r.pwhash     = "scrypt$14$8$1$abc$def";
    r.flags      = sarek::kUserFlagAdmin;
    r.assertions = {"usr:alice", "/*"};

    auto bytes = sarek::pack_user_record(r);
    assert(!bytes.empty());

    auto r2 = sarek::unpack_user_record(bytes);
    assert(r2.user_id    == r.user_id);
    assert(r2.pwhash     == r.pwhash);
    assert(r2.flags      == r.flags);
    assert(r2.assertions == r.assertions);

    std::puts("UserRecord msgpack roundtrip: OK");
}

static void test_needs_bootstrap() {
    sarek::SarekConfig cfg;
    cfg.db_path = "/tmp/sarek_nbs_" + std::to_string(std::rand());

    // Directory doesn't exist → needs bootstrap
    assert(sarek::needs_bootstrap(cfg));

    // Create the env (which creates __db.001 etc.)
    { sarek::SarekEnv env(cfg.db_path); }  // open and immediately close

    assert(!sarek::needs_bootstrap(cfg));

    fs::remove_all(cfg.db_path);
    std::puts("needs_bootstrap: OK");
}

static void test_run_bootstrap() {
    sarek::SarekConfig cfg;
    cfg.db_path    = make_tmpdir();
    cfg.admin_user = "admin";
    cfg.http_port  = 8080;
    cfg.cache_ttl_secs   = 3600;
    cfg.max_data_node_sz = 1048576;

    // Use n_log2=14 for speed (2^14 = 16384 iterations).
    Tray sys_tray = make_tray(TrayType::Level3, "system");
    auto env = sarek::run_bootstrap(cfg, "testpassword", sys_tray, 14);
    assert(env != nullptr);

    // ── tray_alias entries ───────────────────────────────────────────────────
    auto sys_id  = env->tray_alias().get("system");
    auto tok_id  = env->tray_alias().get("system-token");
    assert(sys_id.has_value()  && sys_id->size()  == 16);
    assert(tok_id.has_value()  && tok_id->size()  == 16);
    assert(*sys_id != *tok_id);

    std::puts("bootstrap tray aliases: OK");

    // ── tray records in tray DB ──────────────────────────────────────────────
    auto sys_rec_bytes = env->tray().get(sys_id->data(), sys_id->size());
    auto tok_rec_bytes = env->tray().get(tok_id->data(), tok_id->size());
    assert(sys_rec_bytes.has_value() && !sys_rec_bytes->empty());
    assert(tok_rec_bytes.has_value() && !tok_rec_bytes->empty());

    std::puts("bootstrap tray records: OK");

    // ── system tray in keyring ───────────────────────────────────────────────
    // load_system_tray() must succeed (keyring blob was populated by run_bootstrap)
    Tray kr_tray = sarek::load_system_tray(*env);
    assert(kr_tray.id == sys_tray.id);
    assert(kr_tray.tray_type == TrayType::Level3);

    std::puts("bootstrap system tray in keyring: OK");

    // ── admin user record ────────────────────────────────────────────────────
    auto user_bytes = env->user().get(cfg.admin_user);
    assert(user_bytes.has_value());

    sarek::UserRecord admin = sarek::unpack_user_record(*user_bytes);
    assert(admin.user_id == 1);
    assert(!admin.pwhash.empty());
    assert(admin.flags & sarek::kUserFlagAdmin);

    // Assertions should contain "usr:admin" and "/*"
    bool has_usr = false, has_wildcard = false;
    for (const auto& a : admin.assertions) {
        if (a == "usr:" + cfg.admin_user) has_usr       = true;
        if (a == "/*")                    has_wildcard  = true;
    }
    assert(has_usr && has_wildcard);

    std::puts("bootstrap admin user: OK");

    // ── password verify (n_log2 baked into hash string) ──────────────────────
    assert(sarek::verify_password("testpassword", admin.pwhash));
    assert(!sarek::verify_password("wrongpassword", admin.pwhash));

    std::puts("bootstrap password verify: OK");

    // ── needs_bootstrap returns false now ─────────────────────────────────────
    env.reset();  // close env
    assert(!sarek::needs_bootstrap(cfg));
    std::puts("needs_bootstrap after init: OK");

    fs::remove_all(cfg.db_path);
}

// ---------------------------------------------------------------------------
int main() {
    std::srand(98765);

    test_hash_verify();
    test_user_record_roundtrip();
    test_needs_bootstrap();
    test_run_bootstrap();  // ~0.5s with n_log2=14 (1 scrypt call for admin password)

    std::puts("\nAll bootstrap tests passed.");
    return 0;
}
