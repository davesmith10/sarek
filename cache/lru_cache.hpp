#pragma once

#include <chrono>
#include <list>
#include <mutex>
#include <optional>
#include <unordered_map>
#include <utility>

namespace sarek {

// ---------------------------------------------------------------------------
// LruCache<K, V>
//
// Thread-safe, TTL-aware LRU cache backed by a doubly-linked list (MRU at
// front) and an unordered_map for O(1) lookup.
//
//   max_size    — maximum number of live entries; 0 = unlimited.
//   default_ttl — seconds until an entry expires; 0 = never expire.
// ---------------------------------------------------------------------------
template<typename K, typename V>
class LruCache {
public:
    LruCache(size_t max_size, int default_ttl)
        : max_size_(max_size), default_ttl_(default_ttl) {}

    LruCache(const LruCache&) = delete;
    LruCache& operator=(const LruCache&) = delete;

    // Returns the cached value if present and not expired.
    // An expired entry is removed before returning nullopt.
    std::optional<V> get(const K& key) {
        std::lock_guard<std::mutex> lock(mu_);
        auto it = map_.find(key);
        if (it == map_.end()) return std::nullopt;

        if (is_expired(it->second->expires)) {
            remove_locked(it);
            return std::nullopt;
        }

        // Promote to MRU.
        list_.splice(list_.begin(), list_, it->second);
        return it->second->value;
    }

    // Insert or update.  ttl_override=0 uses the cache-wide default_ttl.
    void put(const K& key, V value, int ttl_override = 0) {
        std::lock_guard<std::mutex> lock(mu_);
        auto expires = make_expiry(ttl_override > 0 ? ttl_override : default_ttl_);

        auto it = map_.find(key);
        if (it != map_.end()) {
            it->second->value   = std::move(value);
            it->second->expires = expires;
            list_.splice(list_.begin(), list_, it->second);
            return;
        }

        list_.push_front({key, std::move(value), expires});
        map_.emplace(key, list_.begin());

        if (max_size_ > 0 && list_.size() > max_size_)
            evict_lru_locked();
    }

    // Remove a specific entry (no-op if absent).
    void evict(const K& key) {
        std::lock_guard<std::mutex> lock(mu_);
        auto it = map_.find(key);
        if (it != map_.end()) remove_locked(it);
    }

    size_t size() const {
        std::lock_guard<std::mutex> lock(mu_);
        return map_.size();
    }

private:
    using clock_t    = std::chrono::steady_clock;
    using time_point = clock_t::time_point;

    struct Entry {
        K          key;
        V          value;
        time_point expires;
    };

    using list_t    = std::list<Entry>;
    using list_iter = typename list_t::iterator;
    using map_t     = std::unordered_map<K, list_iter>;
    using map_iter  = typename map_t::iterator;

    static time_point make_expiry(int ttl_secs) {
        if (ttl_secs <= 0) return time_point::max();
        return clock_t::now() + std::chrono::seconds(ttl_secs);
    }

    static bool is_expired(time_point tp) {
        return tp != time_point::max() && clock_t::now() >= tp;
    }

    void evict_lru_locked() {
        if (list_.empty()) return;
        auto back = std::prev(list_.end());
        map_.erase(back->key);
        list_.erase(back);
    }

    void remove_locked(map_iter it) {
        list_.erase(it->second);
        map_.erase(it);
    }

    mutable std::mutex mu_;
    list_t             list_;       // front = MRU, back = LRU
    map_t              map_;
    size_t             max_size_;
    int                default_ttl_;
};

} // namespace sarek
