#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <db.h>

namespace sarek {

// ---------------------------------------------------------------------------
// Key encoding helpers
// ---------------------------------------------------------------------------

// Encode a uint64_t as 8 big-endian bytes (preserves BTree sort order).
std::array<uint8_t, 8> encode_uint64(uint64_t v);
uint64_t               decode_uint64(const void* data);

// ---------------------------------------------------------------------------
// Forward declarations
// ---------------------------------------------------------------------------
class SarekEnv;
class SarekTxn;

// ---------------------------------------------------------------------------
// SarekDb — RAII wrapper around a single BTree DB handle
// ---------------------------------------------------------------------------
class SarekDb {
public:
    SarekDb() = default;
    ~SarekDb() { close(); }
    SarekDb(const SarekDb&) = delete;
    SarekDb& operator=(const SarekDb&) = delete;

    // Explicit close (idempotent). Called by ~SarekDb and by SarekEnv before
    // closing the environment.
    void close();

    // ---- Raw byte interface ------------------------------------------------
    std::optional<std::vector<uint8_t>> get(
        const void* key_data, size_t key_size, SarekTxn* txn = nullptr);

    void put(
        const void* key_data, size_t key_size,
        const void* val_data, size_t val_size, SarekTxn* txn = nullptr);

    void del(const void* key_data, size_t key_size, SarekTxn* txn = nullptr);

    // ---- String-key convenience -------------------------------------------
    std::optional<std::vector<uint8_t>> get(
        const std::string& key, SarekTxn* txn = nullptr);

    void put(const std::string& key, const std::vector<uint8_t>& val,
             SarekTxn* txn = nullptr);

    void del(const std::string& key, SarekTxn* txn = nullptr);

    // ---- uint64-key convenience (big-endian encoded) ----------------------
    std::optional<std::vector<uint8_t>> get(uint64_t key, SarekTxn* txn = nullptr);
    void put(uint64_t key, const std::vector<uint8_t>& val, SarekTxn* txn = nullptr);
    void del(uint64_t key, SarekTxn* txn = nullptr);

    // ---- Cursor scan -------------------------------------------------------
    // Iterates all records in key order. Callback returns false to stop early.
    void scan(SarekTxn* txn,
              const std::function<bool(const void* k, size_t ksz,
                                       const void* v, size_t vsz)>& cb);

private:
    friend class SarekEnv;
    DB* db_ = nullptr;
};

// ---------------------------------------------------------------------------
// SarekTxn — RAII transaction; aborts automatically unless committed
// ---------------------------------------------------------------------------
class SarekTxn {
public:
    ~SarekTxn();
    SarekTxn(const SarekTxn&) = delete;
    SarekTxn& operator=(const SarekTxn&) = delete;

    void commit();
    void abort();

    DB_TXN* handle() const { return txn_; }

private:
    friend class SarekEnv;
    explicit SarekTxn(DB_TXN* t) : txn_(t) {}

    DB_TXN* txn_  = nullptr;
    bool    done_ = false;
};

// ---------------------------------------------------------------------------
// SarekEnv — BDB environment + all six named databases
// ---------------------------------------------------------------------------
class SarekEnv {
public:
    // Opens (and creates if necessary) the BDB environment at `path` and opens
    // all six named BTree databases within it.
    explicit SarekEnv(const std::string& path);
    ~SarekEnv();
    SarekEnv(const SarekEnv&) = delete;
    SarekEnv& operator=(const SarekEnv&) = delete;

    std::unique_ptr<SarekTxn> begin_txn();

    // Named database accessors
    SarekDb& tray()       { return tray_; }
    SarekDb& tray_alias() { return tray_alias_; }
    SarekDb& user()       { return user_db_; }
    SarekDb& data()       { return data_; }
    SarekDb& metadata()   { return metadata_; }
    SarekDb& path()       { return path_db_; }

private:
    void open_db(SarekDb& db, const char* name);

    DB_ENV* env_ = nullptr;

    SarekDb tray_;
    SarekDb tray_alias_;
    SarekDb user_db_;
    SarekDb data_;
    SarekDb metadata_;
    SarekDb path_db_;
};

} // namespace sarek
