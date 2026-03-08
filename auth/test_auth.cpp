#include "auth/auth.hpp"
#include "bootstrap/bootstrap.hpp"
#include "bootstrap/user_record.hpp"

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <thread>
#include <chrono>

namespace fs = std::filesystem;

static std::string make_tmpdir() {
    return "/tmp/sarek_auth_test_" + std::to_string(std::rand());
}

// ---------------------------------------------------------------------------
static sarek::SarekConfig make_cfg(const std::string& path) {
    sarek::SarekConfig cfg;
    cfg.db_path          = path;
    cfg.admin_user       = "admin";
    cfg.http_port        = 8080;
    cfg.cache_ttl_secs   = 3600;
    cfg.max_data_node_sz = 1048576;
    return cfg;
}

// ---------------------------------------------------------------------------
static void test_issue_validate() {
    std::string dir = make_tmpdir();
    auto cfg = make_cfg(dir);
    auto env = sarek::run_bootstrap(cfg, "secret", 14);

    // Load system-token tray (unencrypted, Level2)
    Tray tok_tray = sarek::load_tray_by_alias(*env, "system-token");
    assert(tok_tray.tray_type == TrayType::Level2);

    // Load admin user
    auto user_opt = sarek::load_user(*env, "admin");
    assert(user_opt.has_value());

    // Issue token
    auto wire = sarek::issue_token(*user_opt, tok_tray);
    assert(!wire.empty());

    // Validate — should return claims
    auto claims = sarek::validate_token(wire, tok_tray);
    assert(claims.username == "admin");

    bool has_wildcard = false, has_usr = false;
    for (const auto& a : claims.assertions) {
        if (a == "/*")         has_wildcard = true;
        if (a == "usr:admin")  has_usr      = true;
    }
    assert(has_wildcard && has_usr);

    std::puts("issue/validate token: OK");

    fs::remove_all(dir);
}

static void test_expired_token() {
    std::string dir = make_tmpdir();
    auto cfg = make_cfg(dir);
    auto env = sarek::run_bootstrap(cfg, "secret", 14);

    Tray tok_tray  = sarek::load_tray_by_alias(*env, "system-token");
    auto user_opt  = sarek::load_user(*env, "admin");

    // Issue with TTL = 1 second
    auto wire = sarek::issue_token(*user_opt, tok_tray, 1);

    std::this_thread::sleep_for(std::chrono::milliseconds(1100));

    bool threw = false;
    try {
        sarek::validate_token(wire, tok_tray);
    } catch (const std::runtime_error& e) {
        std::string msg(e.what());
        threw = (msg.find("expired") != std::string::npos);
    }
    assert(threw);

    std::puts("expired token rejected: OK");

    fs::remove_all(dir);
}

static void test_wrong_tray_rejected() {
    std::string dir = make_tmpdir();
    auto cfg = make_cfg(dir);
    auto env = sarek::run_bootstrap(cfg, "secret", 14);

    Tray tok_tray    = sarek::load_tray_by_alias(*env, "system-token");
    auto user_opt    = sarek::load_user(*env, "admin");
    auto wire        = sarek::issue_token(*user_opt, tok_tray);

    // Attempt to validate against a fresh tray (different UUID + key)
    Tray other_tray = make_tray(TrayType::Level2, "other");

    bool threw = false;
    try {
        sarek::validate_token(wire, other_tray);
    } catch (const std::runtime_error&) {
        threw = true;
    }
    assert(threw);

    std::puts("wrong tray rejected: OK");

    fs::remove_all(dir);
}

static void test_authenticate_user_correct() {
    std::string dir = make_tmpdir();
    auto cfg = make_cfg(dir);
    auto env = sarek::run_bootstrap(cfg, "secret", 14);

    auto result = sarek::authenticate_user(*env, "admin", "secret");
    assert(result.has_value());
    assert(result->user_id == 1);
    assert(result->flags & sarek::kUserFlagAdmin);

    std::puts("authenticate_user correct password: OK");

    fs::remove_all(dir);
}

static void test_authenticate_user_wrong_password() {
    std::string dir = make_tmpdir();
    auto cfg = make_cfg(dir);
    auto env = sarek::run_bootstrap(cfg, "secret", 14);

    auto result = sarek::authenticate_user(*env, "admin", "wrongpassword");
    assert(!result.has_value());

    std::puts("authenticate_user wrong password: OK");

    fs::remove_all(dir);
}

static void test_authenticate_user_not_found() {
    std::string dir = make_tmpdir();
    auto cfg = make_cfg(dir);
    auto env = sarek::run_bootstrap(cfg, "secret", 14);

    bool threw = false;
    try {
        sarek::authenticate_user(*env, "nobody", "secret");
    } catch (const std::runtime_error&) {
        threw = true;
    }
    assert(threw);

    std::puts("authenticate_user not found throws: OK");

    fs::remove_all(dir);
}

static void test_locked_user_rejected() {
    std::string dir = make_tmpdir();
    auto cfg = make_cfg(dir);
    auto env = sarek::run_bootstrap(cfg, "secret", 14);

    // Manually insert a locked user
    sarek::UserRecord locked;
    locked.user_id    = 2;
    locked.pwhash     = sarek::hash_password("pass", 14);
    locked.flags      = sarek::kUserFlagLocked;
    locked.assertions = {"usr:bob"};

    auto bytes = sarek::pack_user_record(locked);
    env->user().put("bob", bytes);

    bool threw = false;
    try {
        sarek::authenticate_user(*env, "bob", "pass");
    } catch (const std::runtime_error& e) {
        std::string msg(e.what());
        threw = (msg.find("locked") != std::string::npos);
    }
    assert(threw);

    std::puts("locked user rejected: OK");

    fs::remove_all(dir);
}

static void test_load_tray_by_alias_encrypted_throws() {
    std::string dir = make_tmpdir();
    auto cfg = make_cfg(dir);
    auto env = sarek::run_bootstrap(cfg, "secret", 14);

    // system tray is PWENC-encrypted; load_tray_by_alias must throw
    bool threw = false;
    try {
        sarek::load_tray_by_alias(*env, "system");
    } catch (const std::runtime_error& e) {
        std::string msg(e.what());
        threw = (msg.find("password-encrypted") != std::string::npos);
    }
    assert(threw);

    std::puts("load encrypted tray throws: OK");

    fs::remove_all(dir);
}

// ---------------------------------------------------------------------------
int main() {
    std::srand(54321);

    test_issue_validate();
    test_wrong_tray_rejected();
    test_authenticate_user_correct();
    test_authenticate_user_wrong_password();
    test_authenticate_user_not_found();
    test_locked_user_rejected();
    test_load_tray_by_alias_encrypted_throws();
    test_expired_token();    // ~1 second sleep

    std::puts("\nAll auth tests passed.");
    return 0;
}
