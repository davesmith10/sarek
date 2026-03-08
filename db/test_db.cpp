#include "db/db.hpp"

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <vector>

namespace fs = std::filesystem;

static std::string make_tmpdir() {
    return "/tmp/sarek_db_test_" + std::to_string(std::rand());
}

static std::vector<uint8_t> bytes(const std::string& s) {
    return {s.begin(), s.end()};
}

static std::string to_str(const std::vector<uint8_t>& v) {
    return {v.begin(), v.end()};
}

// ---------------------------------------------------------------------------
int main() {
    std::srand(12345);
    const std::string dbdir = make_tmpdir();

    {
        sarek::SarekEnv env(dbdir);

        // ── String-key CRUD (path DB) ────────────────────────────────────────
        env.path().put("hello", bytes("world"));
        auto v = env.path().get("hello");
        assert(v.has_value() && to_str(*v) == "world");

        env.path().del("hello");
        assert(!env.path().get("hello").has_value());

        // del on missing key is a no-op (no throw)
        env.path().del("nonexistent");

        std::puts("string key CRUD: OK");

        // ── uint64-key CRUD (data DB) ────────────────────────────────────────
        env.data().put(uint64_t(42), bytes("the answer"));
        auto v2 = env.data().get(uint64_t(42));
        assert(v2.has_value() && to_str(*v2) == "the answer");

        env.data().del(uint64_t(42));
        assert(!env.data().get(uint64_t(42)).has_value());

        std::puts("uint64 key CRUD: OK");

        // ── Big-endian sort order (metadata DB) ──────────────────────────────
        // Insert in reverse; scan must return ascending.
        for (uint64_t i = 5; i >= 1; --i)
            env.metadata().put(i, bytes(std::to_string(i)));

        uint64_t prev = 0;
        int      scan_count = 0;
        env.metadata().scan(nullptr,
            [&](const void* k, size_t ksz, const void*, size_t) -> bool {
                assert(ksz == 8);
                uint64_t key = sarek::decode_uint64(k);
                assert(key > prev);
                prev = key;
                ++scan_count;
                return true;
            });
        assert(scan_count == 5 && prev == 5);

        std::puts("uint64 sort order: OK");

        // ── encode_uint64 / decode_uint64 round-trip ─────────────────────────
        for (uint64_t x : {uint64_t(0), uint64_t(1), UINT64_MAX, uint64_t(0xDEADBEEFCAFEBABEULL)}) {
            auto enc = sarek::encode_uint64(x);
            assert(sarek::decode_uint64(enc.data()) == x);
        }
        std::puts("encode/decode uint64: OK");

        // ── Transaction commit ────────────────────────────────────────────────
        {
            auto txn = env.begin_txn();
            env.user().put("alice", bytes("alice_data"), txn.get());
            txn->commit();
        }
        assert(env.user().get("alice").has_value());
        assert(to_str(*env.user().get("alice")) == "alice_data");

        std::puts("txn commit: OK");

        // ── Transaction abort ─────────────────────────────────────────────────
        {
            auto txn = env.begin_txn();
            env.user().put("bob", bytes("bob_data"), txn.get());
            txn->abort();
        }
        assert(!env.user().get("bob").has_value());

        std::puts("txn abort: OK");

        // ── RAII abort (txn destroyed without commit) ─────────────────────────
        {
            auto txn = env.begin_txn();
            env.user().put("carol", bytes("carol_data"), txn.get());
            // txn goes out of scope → destructor aborts
        }
        assert(!env.user().get("carol").has_value());

        std::puts("txn RAII abort: OK");

        // ── Scan with early stop ───────────────────────────────────────────────
        env.tray_alias().put("alias1", bytes("id1"));
        env.tray_alias().put("alias2", bytes("id2"));
        env.tray_alias().put("alias3", bytes("id3"));

        int full_count = 0;
        env.tray_alias().scan(nullptr,
            [&](const void*, size_t, const void*, size_t) -> bool {
                return ++full_count < 100;
            });
        assert(full_count == 3);

        int stopped_count = 0;
        env.tray_alias().scan(nullptr,
            [&](const void*, size_t, const void*, size_t) -> bool {
                ++stopped_count;
                return false;  // stop after first
            });
        assert(stopped_count == 1);

        std::puts("scan: OK");

        // ── All six DBs reachable ─────────────────────────────────────────────
        env.tray().put("t1", bytes("tray_data"));
        assert(env.tray().get("t1").has_value());

        std::puts("all 6 DBs: OK");
    }
    // SarekEnv destroyed here — checks that close order is safe.

    fs::remove_all(dbdir);

    std::puts("\nAll db tests passed.");
    return 0;
}
