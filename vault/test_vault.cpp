#include "vault/vault.hpp"
#include "bootstrap/bootstrap.hpp"
#include "auth/auth.hpp"

#include <crystals/crystals.hpp>

#include <algorithm>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <string>

namespace fs = std::filesystem;

static std::string make_tmpdir() {
    return "/tmp/sarek_vault_test_" + std::to_string(std::rand());
}

static sarek::SarekConfig make_cfg(const std::string& path) {
    sarek::SarekConfig cfg;
    cfg.db_path          = path;
    cfg.admin_user       = "admin";
    cfg.http_port        = 8080;
    cfg.cache_ttl_secs   = 3600;
    cfg.max_data_node_sz = 1048576;
    return cfg;
}

static Tray make_test_system_tray() {
    return make_tray(TrayType::Level3, "system");
}

// ---------------------------------------------------------------------------
static void test_metadata_roundtrip() {
    sarek::MetadataRecord m;
    m.object_id = 0xDEADBEEFCAFE0001ULL;
    m.created   = 1700000000;
    m.size      = 42;
    m.mimetype  = "text/plain";
    m.tray_id   = "550e8400-e29b-41d4-a716-446655440000";
    m.link_path = "";

    auto bytes = sarek::pack_metadata(m);
    auto m2    = sarek::unpack_metadata(bytes);

    assert(m2.object_id == m.object_id);
    assert(m2.created   == m.created);
    assert(m2.size      == m.size);
    assert(m2.mimetype  == m.mimetype);
    assert(m2.tray_id   == m.tray_id);
    assert(m2.link_path.empty());

    // With link
    m.link_path = "/team-a/secret";
    bytes = sarek::pack_metadata(m);
    m2    = sarek::unpack_metadata(bytes);
    assert(m2.link_path == "/team-a/secret");

    std::puts("metadata roundtrip: OK");
}

// ---------------------------------------------------------------------------
static void test_validate_path() {
    // Valid paths
    sarek::validate_path("/foo");
    sarek::validate_path("/foo/bar");
    sarek::validate_path("/a/b/c/d");

    auto throws = [](const std::string& p) -> bool {
        try { sarek::validate_path(p); return false; }
        catch (const std::invalid_argument&) { return true; }
    };

    assert(throws(""));
    assert(throws("foo"));           // no leading slash
    assert(throws("/foo/"));         // trailing slash
    assert(throws("/foo//bar"));     // double slash
    assert(throws("/foo/./bar"));    // dot component
    assert(throws("/foo/../bar"));   // dotdot component
    assert(throws("/"));             // root (ends with '/', size > 1 rule applies differently)

    std::puts("validate_path: OK");
}

// ---------------------------------------------------------------------------
static void test_obiwan_roundtrip() {
    // Use a fresh Level2 tray for encryption
    Tray tray = make_tray(TrayType::Level2, "test-obiwan");

    std::vector<uint8_t> plaintext = {1, 2, 3, 4, 5, 0xFF, 0x00, 42};

    auto wire = sarek::obiwan_encrypt(plaintext, tray);
    assert(!wire.empty());
    assert(wire.size() > 8 + 2 + 4 + 4); // at least headers

    auto recovered = sarek::obiwan_decrypt(wire, tray);
    assert(recovered == plaintext);

    // Tampered wire should throw
    wire[wire.size() / 2] ^= 0xFF;
    bool threw = false;
    try { sarek::obiwan_decrypt(wire, tray); }
    catch (const std::runtime_error&) { threw = true; }
    assert(threw);

    std::puts("obiwan encrypt/decrypt roundtrip: OK");
}

// ---------------------------------------------------------------------------
static void test_create_and_read_secret() {
    std::string dir = make_tmpdir();
    auto cfg = make_cfg(dir);
    auto env = sarek::run_bootstrap(cfg, "secret", make_test_system_tray(), 14);

    // Use system-token tray (Level2, unencrypted)
    Tray tray = sarek::load_tray_by_alias(*env, "system-token");

    std::vector<uint8_t> data = {'h', 'e', 'l', 'l', 'o'};
    sarek::create_secret(*env, "/team-a/greeting", data, tray, "text/plain");

    auto recovered = sarek::read_secret(*env, "/team-a/greeting");
    assert(recovered == data);

    // Duplicate path throws
    bool threw = false;
    try { sarek::create_secret(*env, "/team-a/greeting", data, tray); }
    catch (const std::runtime_error&) { threw = true; }
    assert(threw);

    std::puts("create_secret / read_secret: OK");

    fs::remove_all(dir);
}

// ---------------------------------------------------------------------------
static void test_read_metadata() {
    std::string dir = make_tmpdir();
    auto cfg = make_cfg(dir);
    auto env = sarek::run_bootstrap(cfg, "secret", make_test_system_tray(), 14);

    Tray tray = sarek::load_tray_by_alias(*env, "system-token");
    std::vector<uint8_t> data = {0xAB, 0xCD};

    sarek::create_secret(*env, "/meta/test", data, tray, "application/octet-stream");

    auto meta = sarek::read_metadata(*env, "/meta/test");
    assert(meta.size      == 2);
    assert(meta.mimetype  == "application/octet-stream");
    assert(meta.tray_id   == tray.id);
    assert(meta.link_path.empty());
    assert(meta.created   > 0);

    std::puts("read_metadata: OK");

    fs::remove_all(dir);
}

// ---------------------------------------------------------------------------
static void test_list_secrets() {
    std::string dir = make_tmpdir();
    auto cfg = make_cfg(dir);
    auto env = sarek::run_bootstrap(cfg, "secret", make_test_system_tray(), 14);

    Tray tray = sarek::load_tray_by_alias(*env, "system-token");
    std::vector<uint8_t> d = {1};

    sarek::create_secret(*env, "/a/x", d, tray);
    sarek::create_secret(*env, "/a/y", d, tray);
    sarek::create_secret(*env, "/b/z", d, tray);

    auto all = sarek::list_secrets(*env, "");
    assert(all.size() == 3);

    auto a_only = sarek::list_secrets(*env, "/a/");
    assert(a_only.size() == 2);

    auto b_only = sarek::list_secrets(*env, "/b/");
    assert(b_only.size() == 1);

    std::puts("list_secrets: OK");

    fs::remove_all(dir);
}

// ---------------------------------------------------------------------------
static void test_create_link() {
    std::string dir = make_tmpdir();
    auto cfg = make_cfg(dir);
    auto env = sarek::run_bootstrap(cfg, "secret", make_test_system_tray(), 14);

    Tray tray = sarek::load_tray_by_alias(*env, "system-token");
    std::vector<uint8_t> data = {'l', 'i', 'n', 'k'};

    sarek::create_secret(*env, "/target", data, tray);
    sarek::create_link(*env, "/target", "/link");

    // read_secret should follow the link
    auto recovered = sarek::read_secret(*env, "/link");
    assert(recovered == data);

    // read_metadata on link returns the link record itself (link_path non-empty)
    auto meta = sarek::read_metadata(*env, "/link");
    assert(meta.link_path == "/target");

    // Duplicate link_path throws
    bool threw = false;
    try { sarek::create_link(*env, "/target", "/link"); }
    catch (const std::runtime_error&) { threw = true; }
    assert(threw);

    std::puts("create_link / follow link: OK");

    fs::remove_all(dir);
}

// ---------------------------------------------------------------------------
static void test_delete_link() {
    std::string dir = make_tmpdir();
    auto cfg = make_cfg(dir);
    auto env = sarek::run_bootstrap(cfg, "secret", make_test_system_tray(), 14);
    Tray tray = sarek::load_tray_by_alias(*env, "system-token");

    std::vector<uint8_t> data = {'d', 'a', 't', 'a'};
    sarek::create_secret(*env, "/target", data, tray);
    sarek::create_link(*env, "/target", "/mylink");

    // delete_link removes path and metadata
    sarek::delete_link(*env, "/mylink");

    // path is gone — read_secret should throw
    bool threw = false;
    try { sarek::read_secret(*env, "/mylink"); }
    catch (const std::runtime_error&) { threw = true; }
    assert(threw);

    // metadata record is also gone
    threw = false;
    try { sarek::read_metadata(*env, "/mylink"); }
    catch (const std::runtime_error&) { threw = true; }
    assert(threw);

    // target is unaffected
    auto recovered = sarek::read_secret(*env, "/target");
    assert(recovered == data);

    // deleting a non-link (real secret) should throw
    threw = false;
    try { sarek::delete_link(*env, "/target"); }
    catch (const std::runtime_error&) { threw = true; }
    assert(threw);

    // deleting a non-existent path should throw
    threw = false;
    try { sarek::delete_link(*env, "/nonexistent"); }
    catch (const std::runtime_error&) { threw = true; }
    assert(threw);

    std::puts("delete_link: OK");
    fs::remove_all(dir);
}

// ---------------------------------------------------------------------------
static void test_create_link_cycle() {
    std::string dir = make_tmpdir();
    auto cfg = make_cfg(dir);
    auto env = sarek::run_bootstrap(cfg, "secret", make_test_system_tray(), 14);

    // Two-node cycle: /a → /b → /a
    sarek::create_link(*env, "/b", "/a");

    // confirm /a was created
    auto meta_a = sarek::read_metadata(*env, "/a");
    assert(meta_a.link_path == "/b");

    bool threw = false;
    try { sarek::create_link(*env, "/a", "/b"); }  // would close the cycle
    catch (const std::runtime_error&) { threw = true; }
    assert(threw);

    // Self-link: /x → /x
    threw = false;
    try { sarek::create_link(*env, "/x", "/x"); }
    catch (const std::runtime_error&) { threw = true; }
    assert(threw);

    std::puts("create_link cycle detection: OK");
    fs::remove_all(dir);
}

// ---------------------------------------------------------------------------
static void test_create_user() {
    std::string dir = make_tmpdir();
    auto cfg = make_cfg(dir);
    auto env = sarek::run_bootstrap(cfg, "secret", make_test_system_tray(), 14);

    sarek::create_user(*env, "alice", "alicepass", sarek::kUserFlagAdmin,
                       {"usr:alice", "/*"}, 42, 14);

    auto result = sarek::authenticate_user(*env, "alice", "alicepass");
    assert(result.has_value());
    assert(result->user_id == 42);

    // Duplicate throws
    bool threw = false;
    try {
        sarek::create_user(*env, "alice", "pass2", 0, {"usr:alice"}, 43, 14);
    } catch (const std::runtime_error&) { threw = true; }
    assert(threw);

    std::puts("create_user: OK");

    fs::remove_all(dir);
}

// ---------------------------------------------------------------------------
static void test_lock_user() {
    std::string dir = make_tmpdir();
    auto cfg = make_cfg(dir);
    auto env = sarek::run_bootstrap(cfg, "secret", make_test_system_tray(), 14);

    sarek::create_user(*env, "bob", "bobpass", 0, {"usr:bob"}, 10, 14);
    sarek::lock_user(*env, "bob");

    bool threw = false;
    try { sarek::authenticate_user(*env, "bob", "bobpass"); }
    catch (const std::runtime_error& e) {
        std::string msg(e.what());
        threw = (msg.find("locked") != std::string::npos);
    }
    assert(threw);

    std::puts("lock_user: OK");

    fs::remove_all(dir);
}

// ---------------------------------------------------------------------------
static void test_store_and_list_trays() {
    std::string dir = make_tmpdir();
    auto cfg = make_cfg(dir);
    auto env = sarek::run_bootstrap(cfg, "secret", make_test_system_tray(), 14);

    Tray t1 = make_tray(TrayType::Level2, "team-a-tray");
    sarek::store_tray(*env, t1, 1);

    // get_tray_by_id
    auto uuid_bytes = [&]() -> std::array<uint8_t, 16> {
        std::string hex;
        for (char c : t1.id) if (c != '-') hex += c;
        std::array<uint8_t, 16> out{};
        auto from_hex = [](char c) -> uint8_t {
            if (c >= '0' && c <= '9') return (uint8_t)(c - '0');
            if (c >= 'a' && c <= 'f') return (uint8_t)(c - 'a' + 10);
            return (uint8_t)(c - 'A' + 10);
        };
        for (int i = 0; i < 16; ++i)
            out[i] = (uint8_t)((from_hex(hex[i*2]) << 4) | from_hex(hex[i*2+1]));
        return out;
    }();

    Tray loaded = sarek::get_tray_by_id(*env, uuid_bytes.data(), 16);
    assert(loaded.id    == t1.id);
    assert(loaded.alias == t1.alias);

    // Duplicate alias throws
    bool threw = false;
    try { sarek::store_tray(*env, t1, 1); }
    catch (const std::runtime_error&) { threw = true; }
    assert(threw);

    // list_trays_for_user
    Tray t2 = make_tray(TrayType::Level2, "team-b-tray");
    sarek::store_tray(*env, t2, 2);

    auto trays_u1 = sarek::list_trays_for_user(*env, 1);
    // admin's bootstrap trays + team-a-tray owned by user 1
    bool found = false;
    for (auto& a : trays_u1) if (a == "team-a-tray") { found = true; break; }
    assert(found);

    auto trays_u2 = sarek::list_trays_for_user(*env, 2);
    found = false;
    for (auto& a : trays_u2) if (a == "team-b-tray") { found = true; break; }
    assert(found);

    std::puts("store_tray / get_tray_by_id / list_trays_for_user: OK");

    fs::remove_all(dir);
}

// ---------------------------------------------------------------------------
static void test_tray_scope_allows() {
    // /* matches any path
    assert(sarek::tray_scope_allows({"/*"}, "/anything"));
    assert(sarek::tray_scope_allows({"/*"}, "/a/b/c"));

    // slc: prefix match
    assert(sarek::tray_scope_allows({"slc:/alice/*"}, "/alice/secrets/x"));
    assert(sarek::tray_scope_allows({"slc:/alice/*"}, "/alice/"));
    assert(!sarek::tray_scope_allows({"slc:/alice/*"}, "/bob/secrets/x"));
    assert(!sarek::tray_scope_allows({"slc:/alice/*"}, "/alicefoo/x"));

    // slc: exact match (no trailing *)
    assert(sarek::tray_scope_allows({"slc:/exact/path"}, "/exact/path"));
    assert(!sarek::tray_scope_allows({"slc:/exact/path"}, "/exact/path/sub"));

    // multiple assertions: any match succeeds
    assert(sarek::tray_scope_allows({"slc:/alice/*", "slc:/team-a/*"}, "/team-a/shared"));
    assert(!sarek::tray_scope_allows({"slc:/alice/*", "slc:/team-a/*"}, "/bob/secret"));

    // empty assertions: always false
    assert(!sarek::tray_scope_allows({}, "/anything"));

    std::puts("tray_scope_allows: OK");
}

// ---------------------------------------------------------------------------
static void test_scope_is_within() {
    using sarek::scope_is_within;

    // --- admin wildcard ---
    // only an admin-scoped caller may request /*
    assert( scope_is_within("/*",           {"/*"}));
    assert(!scope_is_within("/*",           {"slc:/alice/*"}));

    // --- wildcard scope: /prefix/* ---
    // same scope as user
    assert( scope_is_within("slc:/alice/*", {"slc:/alice/*"}));
    // narrower prefix: /alice/scripts/* is within /alice/*
    assert( scope_is_within("slc:/alice/scripts/*", {"slc:/alice/*"}));
    // admin user may request anything
    assert( scope_is_within("slc:/alice/*", {"/*"}));
    // different stem: rejected
    assert(!scope_is_within("slc:/bob/*",   {"slc:/alice/*"}));
    // spec's exact multi-component example
    assert(!scope_is_within("slc:/bob/secret-stuff/*", {"slc:/alice/*"}));
    // partial stem match (not a path boundary): rejected
    assert(!scope_is_within("slc:/alicefoo/*", {"slc:/alice/*"}));
    // wildcard not preceded by /: invalid syntax
    assert(!scope_is_within("slc:/a*",      {"slc:/alice/*"}));
    // bare form (no slc: prefix) also rejected
    assert(!scope_is_within("/a*",          {"slc:/alice/*"}));
    // trailing slash: invalid syntax
    assert(!scope_is_within("slc:/alice/",  {"slc:/alice/*"}));
    // bare form (no slc: prefix) also rejected
    assert(!scope_is_within("/alice/",      {"slc:/alice/*"}));
    // missing slc: prefix
    assert(!scope_is_within("/alice/*",     {"slc:/alice/*"}));

    // --- exact-path scope ---
    // exact path within user's wildcard
    assert( scope_is_within("slc:/alice/myscripts/v1", {"slc:/alice/*"}));
    // exact path outside user's scope
    assert(!scope_is_within("slc:/bob/secret",         {"slc:/alice/*"}));
    // exact path allowed by admin
    assert( scope_is_within("slc:/anything/here",      {"/*"}));

    // --- multiple user assertions ---
    assert( scope_is_within("slc:/team-a/ci/*", {"slc:/alice/*", "slc:/team-a/*"}));
    assert(!scope_is_within("slc:/ops/*",        {"slc:/alice/*", "slc:/team-a/*"}));

    // --- empty user assertions: always false ---
    assert(!scope_is_within("slc:/alice/*", {}));

    std::puts("scope_is_within: OK");
}

// ---------------------------------------------------------------------------
static void test_tray_usable_by() {
    // exact overlap: same prefix
    assert(sarek::tray_usable_by({"slc:/alice/*"}, {"slc:/alice/*"}));

    // user prefix narrower than tray prefix → still overlaps
    assert(sarek::tray_usable_by({"slc:/alice/*"}, {"slc:/alice/secrets/*"}));

    // tray prefix narrower than user prefix → overlaps
    assert(sarek::tray_usable_by({"slc:/alice/secrets/*"}, {"slc:/alice/*"}));

    // disjoint prefixes
    assert(!sarek::tray_usable_by({"slc:/alice/*"}, {"slc:/bob/*"}));

    // /* always overlaps
    assert(sarek::tray_usable_by({"/*"}, {"slc:/anything/*"}));
    assert(sarek::tray_usable_by({"slc:/alice/*"}, {"/*"}));

    // empty on either side
    assert(!sarek::tray_usable_by({}, {"slc:/alice/*"}));
    assert(!sarek::tray_usable_by({"slc:/alice/*"}, {}));

    // exact-path assertions: false positive guard
    // tray slc:/a (exact) + user slc:/ab/* (prefix) must be false
    assert(!sarek::tray_usable_by({"slc:/a"}, {"slc:/ab/*"}));
    // tray slc:/alice/* + user slc:/alice/x (exact) must be true
    assert(sarek::tray_usable_by({"slc:/alice/*"}, {"slc:/alice/x"}));

    std::puts("tray_usable_by: OK");
}

// ---------------------------------------------------------------------------
static void test_tray_assertions_roundtrip() {
    std::string dir = make_tmpdir();
    auto cfg = make_cfg(dir);
    auto env = sarek::run_bootstrap(cfg, "secret", make_test_system_tray(), 14);

    // store_tray with assertions, then get_tray_assertions
    std::vector<std::string> expected = {"slc:/alice/*", "slc:/team-a/*"};
    Tray t = make_tray(TrayType::Level2, "alice-tray");
    sarek::store_tray(*env, t, 1, expected);

    auto got = sarek::get_tray_assertions(*env, t.id);
    assert(got == expected);

    // store_tray with empty assertions → returns empty vector
    Tray t2 = make_tray(TrayType::Level2, "no-assert-tray");
    sarek::store_tray(*env, t2, 1, {});
    auto got2 = sarek::get_tray_assertions(*env, t2.id);
    assert(got2.empty());

    // store_tray_assertions standalone (overwrite)
    auto txn = env->begin_txn();
    sarek::store_tray_assertions(*env, t.id, {"/*"}, txn.get());
    txn->commit();
    auto got3 = sarek::get_tray_assertions(*env, t.id);
    assert(got3 == std::vector<std::string>{"/*"});

    // get_tray_assertions for unknown id returns empty
    auto got4 = sarek::get_tray_assertions(*env, "00000000-0000-0000-0000-000000000000");
    assert(got4.empty());

    // bootstrap seeds system and system-token with ["/*"]
    Tray sys = sarek::load_tray_by_alias(*env, "system");
    auto sys_ass = sarek::get_tray_assertions(*env, sys.id);
    assert(sys_ass == std::vector<std::string>{"/*"});

    Tray tok = sarek::load_tray_by_alias(*env, "system-token");
    auto tok_ass = sarek::get_tray_assertions(*env, tok.id);
    assert(tok_ass == std::vector<std::string>{"/*"});

    std::puts("tray_assertions roundtrip: OK");
    fs::remove_all(dir);
}

// ---------------------------------------------------------------------------
static void test_read_secret_with_cache() {
    std::string dir = make_tmpdir();
    auto cfg = make_cfg(dir);
    auto env = sarek::run_bootstrap(cfg, "secret", make_test_system_tray(), 14);

    Tray tray = sarek::load_tray_by_alias(*env, "system-token");
    std::vector<uint8_t> data = {10, 20, 30};

    sarek::create_secret(*env, "/cached/val", data, tray);

    sarek::LruCache<uint64_t, std::vector<uint8_t>> cache(64, 3600);
    auto r1 = sarek::read_secret(*env, "/cached/val", &cache);
    assert(r1 == data);
    assert(cache.size() == 1);

    // Second read should hit cache (same result)
    auto r2 = sarek::read_secret(*env, "/cached/val", &cache);
    assert(r2 == data);

    std::puts("read_secret with cache: OK");

    fs::remove_all(dir);
}

// ---------------------------------------------------------------------------
static void test_update_secret_basic() {
    std::string dir = make_tmpdir();
    auto cfg = make_cfg(dir);
    auto env = sarek::run_bootstrap(cfg, "secret", make_test_system_tray(), 14);

    Tray tray = sarek::load_tray_by_alias(*env, "system-token");
    std::vector<uint8_t> orig    = {'h', 'e', 'l', 'l', 'o'};
    std::vector<uint8_t> updated = {'w', 'o', 'r', 'l', 'd', '!'};

    sarek::create_secret(*env, "/edit/test", orig, tray, "text/plain");
    sarek::update_secret(*env, "/edit/test", updated, nullptr);

    auto result = sarek::read_secret(*env, "/edit/test");
    assert(result == updated);

    auto meta = sarek::read_metadata(*env, "/edit/test");
    assert(meta.size == updated.size());

    std::puts("update_secret basic: OK");
    fs::remove_all(dir);
}

static void test_update_secret_cache_invalidated() {
    std::string dir = make_tmpdir();
    auto cfg = make_cfg(dir);
    auto env = sarek::run_bootstrap(cfg, "secret", make_test_system_tray(), 14);

    Tray tray = sarek::load_tray_by_alias(*env, "system-token");
    std::vector<uint8_t> orig    = {1, 2, 3};
    std::vector<uint8_t> updated = {4, 5, 6};

    sarek::create_secret(*env, "/cache/test", orig, tray);

    sarek::LruCache<uint64_t, std::vector<uint8_t>> cache(64, 3600);
    sarek::read_secret(*env, "/cache/test", &cache);
    assert(cache.size() == 1);

    sarek::update_secret(*env, "/cache/test", updated, &cache);

    auto meta = sarek::read_metadata(*env, "/cache/test");
    auto cached = cache.get(meta.object_id);
    assert(cached.has_value());
    assert(*cached == updated);

    auto result = sarek::read_secret(*env, "/cache/test", &cache);
    assert(result == updated);

    std::puts("update_secret cache invalidate+refresh: OK");
    fs::remove_all(dir);
}

static void test_update_secret_follows_link() {
    std::string dir = make_tmpdir();
    auto cfg = make_cfg(dir);
    auto env = sarek::run_bootstrap(cfg, "secret", make_test_system_tray(), 14);

    Tray tray = sarek::load_tray_by_alias(*env, "system-token");
    std::vector<uint8_t> orig    = {'a'};
    std::vector<uint8_t> updated = {'b', 'c'};

    sarek::create_secret(*env, "/real/data", orig, tray);
    sarek::create_link(*env, "/real/data", "/link/to/data");

    sarek::update_secret(*env, "/link/to/data", updated, nullptr);

    assert(sarek::read_secret(*env, "/real/data")     == updated);
    assert(sarek::read_secret(*env, "/link/to/data")  == updated);

    std::puts("update_secret follows link: OK");
    fs::remove_all(dir);
}

// ---------------------------------------------------------------------------
static void test_version_increments_on_create() {
    std::string dir = make_tmpdir();
    auto cfg = make_cfg(dir);
    auto env = sarek::run_bootstrap(cfg, "secret", make_test_system_tray(), 14);

    Tray tray = sarek::load_tray_by_alias(*env, "system-token");
    std::vector<uint8_t> data = {'h', 'e', 'l', 'l', 'o'};

    sarek::create_secret(*env, "/ver/test", data, tray, "text/plain");

    auto meta = sarek::read_metadata(*env, "/ver/test");
    assert(meta.version == 1);

    // Test that version increments on update
    std::vector<uint8_t> updated = {'w', 'o', 'r', 'l', 'd'};
    sarek::update_secret(*env, "/ver/test", updated, nullptr);

    meta = sarek::read_metadata(*env, "/ver/test");
    assert(meta.version == 2);

    // Test that version increments again on second update
    std::vector<uint8_t> updated2 = {'f', 'o', 'o', 'b', 'a', 'r'};
    sarek::update_secret(*env, "/ver/test", updated2, nullptr);

    meta = sarek::read_metadata(*env, "/ver/test");
    assert(meta.version == 3);

    std::puts("version increments on create: OK");
    std::puts("version increments on update: OK");
    fs::remove_all(dir);
}

// ---------------------------------------------------------------------------
static void test_etag_match_succeeds() {
    std::string dir = make_tmpdir();
    auto cfg = make_cfg(dir);
    auto env = sarek::run_bootstrap(cfg, "secret", make_test_system_tray(), 14);

    Tray tray = sarek::load_tray_by_alias(*env, "system-token");
    std::vector<uint8_t> v1 = {'v', '1'};
    std::vector<uint8_t> v2 = {'v', '2'};

    sarek::create_secret(*env, "/etag/match", v1, tray, "text/plain");

    auto meta = sarek::read_metadata(*env, "/etag/match");
    assert(meta.version == 1);

    sarek::update_secret(*env, "/etag/match", v2, nullptr, meta.version);

    meta = sarek::read_metadata(*env, "/etag/match");
    assert(meta.version == 2);

    std::puts("etag match succeeds: OK");
    fs::remove_all(dir);
}

// ---------------------------------------------------------------------------
static void test_etag_mismatch_throws() {
    std::string dir = make_tmpdir();
    auto cfg = make_cfg(dir);
    auto env = sarek::run_bootstrap(cfg, "secret", make_test_system_tray(), 14);

    Tray tray = sarek::load_tray_by_alias(*env, "system-token");
    std::vector<uint8_t> v1 = {'v', '1'};
    std::vector<uint8_t> v2 = {'v', '2'};

    sarek::create_secret(*env, "/etag/mismatch", v1, tray, "text/plain");

    bool threw = false;
    try {
        sarek::update_secret(*env, "/etag/mismatch", v2, nullptr, 99);
    } catch (const sarek::ETagMismatch&) {
        threw = true;
    }
    assert(threw);

    // Data should still be v1 (rollback worked)
    auto result = sarek::read_secret(*env, "/etag/mismatch");
    assert(result == v1);

    // Version should still be 1
    auto meta = sarek::read_metadata(*env, "/etag/mismatch");
    assert(meta.version == 1);

    std::puts("etag mismatch throws: OK");
    fs::remove_all(dir);
}

// ---------------------------------------------------------------------------
static void test_etag_zero_skips_check() {
    std::string dir = make_tmpdir();
    auto cfg = make_cfg(dir);
    auto env = sarek::run_bootstrap(cfg, "secret", make_test_system_tray(), 14);

    Tray tray = sarek::load_tray_by_alias(*env, "system-token");
    std::vector<uint8_t> v1 = {'v', '1'};
    std::vector<uint8_t> v2 = {'v', '2'};

    sarek::create_secret(*env, "/etag/zero", v1, tray, "text/plain");

    // expected_version=0 means skip check
    sarek::update_secret(*env, "/etag/zero", v2, nullptr, 0);

    auto meta = sarek::read_metadata(*env, "/etag/zero");
    assert(meta.version == 2);

    std::puts("etag zero skips check: OK");
    fs::remove_all(dir);
}

// ---------------------------------------------------------------------------
static void test_delete_user_purges_assertions() {
    std::string dir = make_tmpdir();
    auto cfg = make_cfg(dir);
    auto env = sarek::run_bootstrap(cfg, "secret", make_test_system_tray(), 14);

    // Create user alice (user_id 2) with a tray
    sarek::UserRecord alice;
    alice.user_id    = 2;
    alice.pwhash     = sarek::hash_password("pw", 10);
    alice.flags      = 0;
    alice.assertions = {"usr:alice", "slc:/alice/*"};
    auto ab = sarek::pack_user_record(alice);
    env->user().put("alice", ab);

    Tray t = make_tray(TrayType::Level2, "alice-tray");
    sarek::store_tray(*env, t, 2, {"slc:/alice/*"});

    // Assertions exist before delete
    auto before = sarek::get_tray_assertions(*env, t.id);
    assert(!before.empty());

    sarek::delete_user(*env, "alice");

    // Tray assertions must be gone after delete
    auto after = sarek::get_tray_assertions(*env, t.id);
    assert(after.empty());

    std::puts("delete_user purges tray_assertions: OK");
    fs::remove_all(dir);
}

// ---------------------------------------------------------------------------
static void test_migrate_admin_assertion() {
    std::string dir = make_tmpdir();
    auto cfg = make_cfg(dir);
    // Bootstrap creates admin. After Task 2 is done, bootstrap will add "adm:true"
    // automatically. This test strips it if present to simulate a pre-migration DB,
    // then verifies migration adds it back.
    auto env = sarek::run_bootstrap(cfg, "secret", make_test_system_tray(), 14);

    // Strip "adm:true" from admin record to simulate a pre-migration database.
    {
        auto bytes = env->user().get(cfg.admin_user);
        assert(bytes.has_value());
        sarek::UserRecord rec = sarek::unpack_user_record(*bytes);
        rec.assertions.erase(
            std::remove(rec.assertions.begin(), rec.assertions.end(), std::string("adm:true")),
            rec.assertions.end());
        env->user().put(cfg.admin_user, sarek::pack_user_record(rec));
    }

    // First migration: must return 1 (admin record updated).
    int n = sarek::migrate_admin_assertion(*env);
    assert(n == 1);

    // Admin record must now contain "adm:true" and retain pre-existing assertions.
    {
        auto bytes = env->user().get(cfg.admin_user);
        assert(bytes.has_value());
        sarek::UserRecord rec = sarek::unpack_user_record(*bytes);
        bool has_adm = false, has_usr = false, has_scope = false;
        for (const auto& a : rec.assertions) {
            if (a == "adm:true")                has_adm   = true;
            if (a == "usr:" + cfg.admin_user)   has_usr   = true;
            if (a == "/*")                      has_scope = true;
        }
        assert(has_adm);    // new assertion present
        assert(has_usr);    // original usr: assertion preserved
        assert(has_scope);  // original /* scope preserved
    }

    // Second call must return 0 (idempotent).
    int n2 = sarek::migrate_admin_assertion(*env);
    assert(n2 == 0);

    // Non-admin user must not receive "adm:true".
    sarek::create_user(*env, "bob", "bobpass", 0, {"usr:bob"}, 99, 14);
    int n3 = sarek::migrate_admin_assertion(*env);
    assert(n3 == 0);
    {
        auto bytes = env->user().get("bob");
        assert(bytes.has_value());
        sarek::UserRecord rec = sarek::unpack_user_record(*bytes);
        bool has_adm = false;
        for (const auto& a : rec.assertions)
            if (a == "adm:true") { has_adm = true; break; }
        assert(!has_adm);
    }

    std::puts("migrate_admin_assertion: OK");
    fs::remove_all(dir);
}

// ---------------------------------------------------------------------------
int main() {
    std::srand(99999);

    test_metadata_roundtrip();
    test_validate_path();
    test_obiwan_roundtrip();
    test_create_and_read_secret();
    test_read_metadata();
    test_list_secrets();
    test_create_link();
    test_delete_link();
    test_create_link_cycle();
    test_create_user();
    test_lock_user();
    test_store_and_list_trays();
    test_tray_scope_allows();
    test_scope_is_within();
    test_tray_usable_by();
    test_tray_assertions_roundtrip();
    test_delete_user_purges_assertions();
    test_read_secret_with_cache();
    test_update_secret_basic();
    test_update_secret_cache_invalidated();
    test_update_secret_follows_link();
    test_version_increments_on_create();
    test_etag_match_succeeds();
    test_etag_mismatch_throws();
    test_etag_zero_skips_check();
    test_migrate_admin_assertion();

    std::puts("\nAll vault tests passed.");
    return 0;
}
