#include "db.hpp"
#include "log/log.hpp"

#include <cstdlib>
#include <filesystem>
#include <stdexcept>
#include <string>

namespace sarek {

// ---------------------------------------------------------------------------
// Key encoding
// ---------------------------------------------------------------------------

std::array<uint8_t, 8> encode_uint64(uint64_t v) {
    std::array<uint8_t, 8> out{};
    out[0] = static_cast<uint8_t>(v >> 56);
    out[1] = static_cast<uint8_t>(v >> 48);
    out[2] = static_cast<uint8_t>(v >> 40);
    out[3] = static_cast<uint8_t>(v >> 32);
    out[4] = static_cast<uint8_t>(v >> 24);
    out[5] = static_cast<uint8_t>(v >> 16);
    out[6] = static_cast<uint8_t>(v >>  8);
    out[7] = static_cast<uint8_t>(v      );
    return out;
}

uint64_t decode_uint64(const void* data) {
    const auto* p = static_cast<const uint8_t*>(data);
    return (static_cast<uint64_t>(p[0]) << 56) |
           (static_cast<uint64_t>(p[1]) << 48) |
           (static_cast<uint64_t>(p[2]) << 40) |
           (static_cast<uint64_t>(p[3]) << 32) |
           (static_cast<uint64_t>(p[4]) << 24) |
           (static_cast<uint64_t>(p[5]) << 16) |
           (static_cast<uint64_t>(p[6]) <<  8) |
           (static_cast<uint64_t>(p[7])      );
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

static DBT make_dbt_ro(const void* data, size_t size) {
    DBT d{};
    d.data = const_cast<void*>(data);
    d.size = static_cast<u_int32_t>(size);
    return d;
}

static void bdb_check(int ret, const char* ctx) {
    if (ret != 0)
        throw std::runtime_error(std::string(ctx) + ": " + db_strerror(ret));
}

// ---------------------------------------------------------------------------
// SarekDb
// ---------------------------------------------------------------------------

void SarekDb::close() {
    if (db_) {
        db_->close(db_, 0);
        db_ = nullptr;
    }
}

std::optional<std::vector<uint8_t>> SarekDb::get(
        const void* key_data, size_t key_size, SarekTxn* txn) {
    DBT key = make_dbt_ro(key_data, key_size);
    DBT val{};
    val.flags = DB_DBT_MALLOC;

    int ret = db_->get(db_, txn ? txn->handle() : nullptr, &key, &val, 0);
    if (ret == DB_NOTFOUND) return std::nullopt;
    bdb_check(ret, "SarekDb::get");

    std::vector<uint8_t> out(
        static_cast<const uint8_t*>(val.data),
        static_cast<const uint8_t*>(val.data) + val.size);
    std::free(val.data);
    return out;
}

void SarekDb::put(
        const void* key_data, size_t key_size,
        const void* val_data, size_t val_size, SarekTxn* txn) {
    DBT key = make_dbt_ro(key_data, key_size);
    DBT val = make_dbt_ro(val_data, val_size);
    bdb_check(db_->put(db_, txn ? txn->handle() : nullptr, &key, &val, 0),
              "SarekDb::put");
}

void SarekDb::del(const void* key_data, size_t key_size, SarekTxn* txn) {
    DBT key = make_dbt_ro(key_data, key_size);
    int ret = db_->del(db_, txn ? txn->handle() : nullptr, &key, 0);
    if (ret == DB_NOTFOUND) return;  // idempotent
    bdb_check(ret, "SarekDb::del");
}

// String-key convenience
std::optional<std::vector<uint8_t>> SarekDb::get(
        const std::string& key, SarekTxn* txn) {
    return get(key.data(), key.size(), txn);
}
void SarekDb::put(const std::string& key, const std::vector<uint8_t>& val,
                  SarekTxn* txn) {
    put(key.data(), key.size(), val.data(), val.size(), txn);
}

bool SarekDb::put_if_absent(const std::string& key,
                             const std::vector<uint8_t>& val,
                             SarekTxn* txn) {
    DBT k = make_dbt_ro(key.data(), key.size());
    DBT v = make_dbt_ro(val.data(), val.size());
    int ret = db_->put(db_, txn ? txn->handle() : nullptr, &k, &v,
                       DB_NOOVERWRITE);
    if (ret == DB_KEYEXIST) return false;
    bdb_check(ret, "SarekDb::put_if_absent");
    return true;
}

void SarekDb::del(const std::string& key, SarekTxn* txn) {
    del(key.data(), key.size(), txn);
}

// uint64-key convenience
std::optional<std::vector<uint8_t>> SarekDb::get(uint64_t key, SarekTxn* txn) {
    auto k = encode_uint64(key);
    return get(k.data(), k.size(), txn);
}
void SarekDb::put(uint64_t key, const std::vector<uint8_t>& val, SarekTxn* txn) {
    auto k = encode_uint64(key);
    put(k.data(), k.size(), val.data(), val.size(), txn);
}
void SarekDb::del(uint64_t key, SarekTxn* txn) {
    auto k = encode_uint64(key);
    del(k.data(), k.size(), txn);
}

// Cursor scan
void SarekDb::scan(SarekTxn* txn,
                   const std::function<bool(const void*, size_t,
                                            const void*, size_t)>& cb) {
    DBC* cursor = nullptr;
    bdb_check(db_->cursor(db_, txn ? txn->handle() : nullptr, &cursor, 0),
              "SarekDb::scan cursor_open");

    DBT key{}, val{};
    key.flags = DB_DBT_MALLOC;
    val.flags = DB_DBT_MALLOC;

    int ret;
    bool stop = false;
    while (!stop && (ret = cursor->get(cursor, &key, &val, DB_NEXT)) == 0) {
        stop = !cb(key.data, key.size, val.data, val.size);
        std::free(key.data); key.data = nullptr; key.size = 0;
        std::free(val.data); val.data = nullptr; val.size = 0;
    }
    if (key.data) std::free(key.data);
    if (val.data) std::free(val.data);
    cursor->close(cursor);

    if (ret != 0 && ret != DB_NOTFOUND)
        bdb_check(ret, "SarekDb::scan");
}

void SarekDb::truncate(SarekTxn* txn) {
    uint32_t count = 0;
    bdb_check(db_->truncate(db_, txn ? txn->handle() : nullptr, &count, 0),
              "SarekDb::truncate");
}

// ---------------------------------------------------------------------------
// SarekTxn
// ---------------------------------------------------------------------------

SarekTxn::~SarekTxn() {
    if (!done_ && txn_) {
        txn_->abort(txn_);
        txn_  = nullptr;
        done_ = true;
    }
}

void SarekTxn::commit() {
    if (done_) return;
    int ret = txn_->commit(txn_, 0);
    txn_  = nullptr;
    done_ = true;
    bdb_check(ret, "SarekTxn::commit");
    get_logger()->debug("db.txn.commit");
}

void SarekTxn::abort() {
    if (done_) return;
    txn_->abort(txn_);
    txn_  = nullptr;
    done_ = true;
    get_logger()->warn("db.txn.abort");
}

// ---------------------------------------------------------------------------
// SarekEnv
// ---------------------------------------------------------------------------

SarekEnv::SarekEnv(const std::string& path) {
    std::filesystem::create_directories(path);

    bdb_check(db_env_create(&env_, 0), "db_env_create");

    // BDB error callback → spdlog
    env_->set_errcall(env_, [](const DB_ENV*, const char* prefix, const char* msg) {
        auto log = get_logger();
        if (log) log->error("bdb: {} {}", prefix ? prefix : "", msg ? msg : "");
    });

    constexpr u_int32_t flags =
        DB_CREATE | DB_INIT_MPOOL | DB_INIT_LOCK | DB_INIT_LOG | DB_INIT_TXN;
    int ret = env_->open(env_, path.c_str(), flags, 0664);
    if (ret != 0) {
        env_->close(env_, 0);
        env_ = nullptr;
        throw std::runtime_error(std::string("SarekEnv::open: ") + db_strerror(ret));
    }

    get_logger()->info("db.open: path={}", path);

    try {
        for (const char* name : {"tray", "tray_alias", "user", "data", "metadata",
                          "path", "manage_token", "wrapped", "wrapper_lookup",
                          "tray_assertions"})
            get_logger()->info("db.open: database={}", name);

        open_db(tray_,             "tray");
        open_db(tray_alias_,       "tray_alias");
        open_db(user_db_,          "user");
        open_db(data_,             "data");
        open_db(metadata_,         "metadata");
        open_db(path_db_,          "path");
        open_db(manage_token_db_,  "manage_token");
        open_db(wrapped_db_,       "wrapped");
        open_db(wrapper_lookup_db_, "wrapper_lookup");
        open_db(tray_assertions_db_, "tray_assertions");
    } catch (...) {
        // Close any that opened successfully before re-throwing.
        tray_.close(); tray_alias_.close(); user_db_.close();
        data_.close(); metadata_.close();   path_db_.close();
        manage_token_db_.close(); wrapped_db_.close(); wrapper_lookup_db_.close();
        tray_assertions_db_.close();
        env_->close(env_, 0);
        env_ = nullptr;
        throw;
    }
}

SarekEnv::~SarekEnv() {
    // Databases must be closed before the environment.
    tray_.close();
    tray_alias_.close();
    user_db_.close();
    data_.close();
    metadata_.close();
    path_db_.close();
    manage_token_db_.close();
    wrapped_db_.close();
    wrapper_lookup_db_.close();
    tray_assertions_db_.close();

    if (env_) {
        env_->close(env_, 0);
        env_ = nullptr;
    }
    // SarekDb member destructors run after this body — close() is idempotent.
    auto log = get_logger();
    if (log) log->info("db.close");
}

void SarekEnv::open_db(SarekDb& db, const char* name) {
    bdb_check(db_create(&db.db_, env_, 0),
              (std::string("db_create(") + name + ")").c_str());

    int ret = db.db_->open(db.db_, nullptr, name, nullptr,
                           DB_BTREE, DB_CREATE | DB_AUTO_COMMIT, 0664);
    if (ret != 0) {
        db.db_->close(db.db_, 0);
        db.db_ = nullptr;
        throw std::runtime_error(
            std::string("DB::open(") + name + "): " + db_strerror(ret));
    }
}

std::unique_ptr<SarekTxn> SarekEnv::begin_txn() {
    DB_TXN* txn = nullptr;
    bdb_check(env_->txn_begin(env_, nullptr, &txn, 0), "txn_begin");
    return std::unique_ptr<SarekTxn>(new SarekTxn(txn));
}

void SarekEnv::set_system_tray_keyring(KeyringBlob&& blob) {
    system_tray_blob_ = std::move(blob);
}

std::vector<uint8_t> SarekEnv::get_system_tray_bytes() const {
    if (!system_tray_blob_)
        throw std::runtime_error("system tray has not been loaded into keyring");
    return system_tray_blob_->load();
}

} // namespace sarek
