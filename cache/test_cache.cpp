#include "cache/lru_cache.hpp"

#include <cassert>
#include <chrono>
#include <cstdio>
#include <string>
#include <thread>
#include <vector>

// ---------------------------------------------------------------------------
static void test_basic_put_get() {
    sarek::LruCache<std::string, int> cache(10, 0);

    cache.put("a", 1);
    cache.put("b", 2);

    auto v = cache.get("a");
    assert(v.has_value() && *v == 1);
    auto v2 = cache.get("b");
    assert(v2.has_value() && *v2 == 2);
    assert(!cache.get("missing").has_value());
    assert(cache.size() == 2);

    std::puts("basic put/get: OK");
}

static void test_evict() {
    sarek::LruCache<std::string, int> cache(10, 0);
    cache.put("x", 42);
    assert(cache.get("x").has_value());

    cache.evict("x");
    assert(!cache.get("x").has_value());
    assert(cache.size() == 0);

    cache.evict("nonexistent");  // must not throw

    std::puts("evict: OK");
}

static void test_lru_eviction_at_capacity() {
    sarek::LruCache<int, std::string> cache(3, 0);
    cache.put(1, "one");
    cache.put(2, "two");
    cache.put(3, "three");
    assert(cache.size() == 3);

    // Access 1 and 2 → they become MRU; 3 is now LRU.
    cache.get(1);
    cache.get(2);

    // Insert 4 → evicts LRU (3).
    cache.put(4, "four");
    assert(cache.size() == 3);
    assert(!cache.get(3).has_value());
    assert(cache.get(1).has_value());
    assert(cache.get(2).has_value());
    assert(cache.get(4).has_value());

    std::puts("LRU eviction at capacity: OK");
}

static void test_update_existing() {
    sarek::LruCache<std::string, int> cache(3, 0);

    // put("k") then update it; k becomes MRU after update.
    cache.put("k", 1);
    cache.put("k", 2);
    auto v = cache.get("k");
    assert(v.has_value() && *v == 2);
    assert(cache.size() == 1);

    // Fill cache: after put("a") and put("b"), order is b(MRU), a, k(LRU).
    cache.put("a", 10);
    cache.put("b", 20);
    // Insert "c" → evicts LRU which is k.
    cache.put("c", 30);
    assert(!cache.get("k").has_value());
    assert(cache.get("a").has_value());
    assert(cache.get("b").has_value());
    assert(cache.get("c").has_value());

    std::puts("update existing: OK");
}

static void test_no_expiry() {
    sarek::LruCache<std::string, int> cache(10, 0);  // default_ttl=0 → never expire
    cache.put("forever", 7);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    assert(cache.get("forever").has_value());

    std::puts("no expiry (TTL=0): OK");
}

static void test_ttl_expiry() {
    sarek::LruCache<std::string, int> cache(10, 0);
    cache.put("short", 99, 1);  // ttl_override = 1 second

    assert(cache.get("short").has_value());
    assert(cache.size() == 1);

    std::this_thread::sleep_for(std::chrono::milliseconds(1100));

    assert(!cache.get("short").has_value());
    assert(cache.size() == 0);  // evicted on miss

    std::puts("TTL expiry: OK");
}

static void test_default_ttl() {
    sarek::LruCache<std::string, int> cache(10, 1);  // default_ttl = 1 second
    cache.put("a", 1);                                // uses default 1s TTL
    cache.put("b", 2, 60);                            // override: 60 seconds

    std::this_thread::sleep_for(std::chrono::milliseconds(1100));

    assert(!cache.get("a").has_value());  // expired
    assert(cache.get("b").has_value());   // still alive

    std::puts("default TTL: OK");
}

static void test_unlimited_size() {
    sarek::LruCache<int, int> cache(0, 0);  // max_size=0 → unlimited
    for (int i = 0; i < 1000; ++i)
        cache.put(i, i * 2);
    assert(cache.size() == 1000);
    for (int i = 0; i < 1000; ++i) {
        auto v = cache.get(i);
        assert(v.has_value() && *v == i * 2);
    }

    std::puts("unlimited size: OK");
}

static void test_thread_safety() {
    sarek::LruCache<int, int> cache(100, 0);
    constexpr int N       = 300;
    constexpr int THREADS = 8;

    std::vector<std::thread> threads;
    threads.reserve(THREADS);
    for (int t = 0; t < THREADS; ++t) {
        threads.emplace_back([&, t]() {
            for (int i = 0; i < N; ++i) {
                cache.put(i % 150, t * 1000 + i);
                cache.get(i % 150);
                if (i % 10 == 0) cache.evict(i % 50);
            }
        });
    }
    for (auto& th : threads) th.join();
    // No value assertions — just verifying no crash or deadlock.

    std::puts("thread safety: OK");
}

// ---------------------------------------------------------------------------
int main() {
    test_basic_put_get();
    test_evict();
    test_lru_eviction_at_capacity();
    test_update_existing();
    test_no_expiry();
    test_unlimited_size();
    test_thread_safety();
    test_ttl_expiry();    // ~1 second sleep
    test_default_ttl();   // ~1 second sleep

    std::puts("\nAll cache tests passed.");
    return 0;
}
