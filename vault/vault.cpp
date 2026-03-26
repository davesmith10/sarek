#include "vault/vault.hpp"
#include "bootstrap/user_record.hpp"
#include "log/log.hpp"

#include <crystals/crystals.hpp>

#include <msgpack.hpp>

#include <openssl/rand.h>

#include <unistd.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <set>
#include <stdexcept>
#include <unordered_set>
#include <string>
#include <vector>

namespace sarek {

static constexpr int kMaxLinkDepth = 8;

// ---------------------------------------------------------------------------
// Wire helpers for unarmored OBIWAN
// ---------------------------------------------------------------------------

static void push_be32(std::vector<uint8_t>& buf, uint32_t v) {
    buf.push_back((v >> 24) & 0xFF);
    buf.push_back((v >> 16) & 0xFF);
    buf.push_back((v >>  8) & 0xFF);
    buf.push_back((v >>  0) & 0xFF);
}

static uint32_t read_be32(const uint8_t* p) {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) |
           (uint32_t(p[2]) <<  8) |  uint32_t(p[3]);
}

// ---------------------------------------------------------------------------
// MetadataRecord pack / unpack  (msgpack, short keys)
//   "id" → object_id (uint64)
//   "cr" → created   (int64)
//   "sz" → size      (uint64)
//   "mt" → mimetype  (str)
//   "tr" → tray_id   (str)
//   "lk" → link_path (str, optional — omitted when empty)
// ---------------------------------------------------------------------------

std::vector<uint8_t> pack_metadata(const MetadataRecord& m) {
    const bool has_link    = !m.link_path.empty();
    const bool has_creator = (m.creator_id != 0);
    const uint32_t map_size = 5 + (has_link ? 1 : 0) + (has_creator ? 1 : 0);

    msgpack::sbuffer buf;
    msgpack::packer<msgpack::sbuffer> pk(buf);

    pk.pack_map(map_size);
    pk.pack(std::string("id")); pk.pack_uint64(m.object_id);
    pk.pack(std::string("cr")); pk.pack_int64(m.created);
    pk.pack(std::string("sz")); pk.pack_uint64(m.size);
    pk.pack(std::string("mt")); pk.pack(m.mimetype);
    pk.pack(std::string("tr")); pk.pack(m.tray_id);
    if (has_link) {
        pk.pack(std::string("lk")); pk.pack(m.link_path);
    }
    if (has_creator) {
        pk.pack(std::string("ow")); pk.pack_uint64(m.creator_id);
    }

    return {reinterpret_cast<const uint8_t*>(buf.data()),
            reinterpret_cast<const uint8_t*>(buf.data()) + buf.size()};
}

MetadataRecord unpack_metadata(const std::vector<uint8_t>& data) {
    msgpack::object_handle oh = msgpack::unpack(
        reinterpret_cast<const char*>(data.data()), data.size());
    const msgpack::object& obj = oh.get();

    if (obj.type != msgpack::type::MAP)
        throw std::runtime_error("unpack_metadata: expected map");

    MetadataRecord m;
    const auto& map = obj.via.map;
    for (uint32_t i = 0; i < map.size; ++i) {
        const auto& kv = map.ptr[i];
        if (kv.key.type != msgpack::type::STR) continue;
        std::string key{kv.key.via.str.ptr, kv.key.via.str.size};

        if (key == "id") {
            m.object_id = kv.val.as<uint64_t>();
        } else if (key == "cr") {
            m.created = kv.val.as<int64_t>();
        } else if (key == "sz") {
            m.size = kv.val.as<uint64_t>();
        } else if (key == "mt") {
            m.mimetype.assign(kv.val.via.str.ptr, kv.val.via.str.size);
        } else if (key == "tr") {
            m.tray_id.assign(kv.val.via.str.ptr, kv.val.via.str.size);
        } else if (key == "lk") {
            m.link_path.assign(kv.val.via.str.ptr, kv.val.via.str.size);
        } else if (key == "ow") {
            m.creator_id = kv.val.as<uint64_t>();
        }
    }
    return m;
}

// ---------------------------------------------------------------------------
// validate_path
// ---------------------------------------------------------------------------

void validate_path(const std::string& path) {
    if (path.empty() || path[0] != '/')
        throw std::invalid_argument("validate_path: path must start with '/'");
    if (path == "/")
        throw std::invalid_argument("validate_path: root '/' is not a valid secret path");
    if (path.back() == '/')
        throw std::invalid_argument("validate_path: path must not end with '/'");
    if (path.find("//") != std::string::npos)
        throw std::invalid_argument("validate_path: path must not contain '//'");

    // Check each component for '.' and '..'
    size_t i = 1;
    while (i < path.size()) {
        size_t slash = path.find('/', i);
        std::string component = (slash == std::string::npos)
            ? path.substr(i)
            : path.substr(i, slash - i);
        if (component == "." || component == "..")
            throw std::invalid_argument(
                "validate_path: path must not contain '.' or '..' components");
        i = (slash == std::string::npos) ? path.size() : slash + 1;
    }
}

// ---------------------------------------------------------------------------
// Unarmored OBIWAN encrypt / decrypt
// ---------------------------------------------------------------------------

std::vector<uint8_t> obiwan_encrypt(const std::vector<uint8_t>& plaintext,
                                     const Tray& tray) {
    if (tray.slots.empty())
        throw std::runtime_error("obiwan_encrypt: tray has no slots");

    // ---- Classical KEM ----
    std::vector<uint8_t> ct_classical, ss_classical;
    if (tray.profile_group == "mceliece+slhdsa") {
        if (tray.slots.size() >= 2) {
            // McEliece Level2+: slot[0] is classical EC
            ec_kem::encaps(tray.slots[0].alg_name, tray.slots[0].pk,
                           ct_classical, ss_classical);
        }
        // McEliece Level1: no classical slot — ct_classical stays empty
    } else {
        // crystals group: slot[0] is EC
        ec_kem::encaps(tray.slots[0].alg_name, tray.slots[0].pk,
                       ct_classical, ss_classical);
    }

    // ---- PQ KEM ----
    // slot[0] for McEliece Level1 (single-slot); slot[1] for all others
    const Slot& kem_pq = (tray.slots.size() == 1) ? tray.slots[0] : tray.slots[1];
    std::vector<uint8_t> ct_pq, ss_pq;
    if (tray.profile_group == "mceliece+slhdsa") {
        mceliece_kem::encaps(kem_pq.alg_name, kem_pq.pk, ct_pq, ss_pq);
    } else {
        kyber_kem::encaps(kyber_kem::level_from_alg(kem_pq.alg_name),
                          kem_pq.pk, ct_pq, ss_pq);
    }

    // Derive key
    auto key = derive_key_shake(ss_classical, ss_pq, ct_classical, ct_pq);

    // Encrypt
    auto payload = aes256gcm_encrypt(key.data(), plaintext);

    // Pack wire bytes (no base64)
    std::vector<uint8_t> wire;
    wire.reserve(8 + 2 + 4 + ct_classical.size() + 4 + ct_pq.size() + payload.size());

    // Magic
    const char* magic = "OBIWAN01";
    wire.insert(wire.end(), magic, magic + 8);
    // KDF byte (0 = SHAKE256) + Cipher byte (0 = AES-256-GCM)
    wire.push_back(0x00);
    wire.push_back(0x00);
    // CT lengths + data
    push_be32(wire, static_cast<uint32_t>(ct_classical.size()));
    wire.insert(wire.end(), ct_classical.begin(), ct_classical.end());
    push_be32(wire, static_cast<uint32_t>(ct_pq.size()));
    wire.insert(wire.end(), ct_pq.begin(), ct_pq.end());
    // Payload
    wire.insert(wire.end(), payload.begin(), payload.end());

    return wire;
}

std::vector<uint8_t> obiwan_decrypt(const std::vector<uint8_t>& wire,
                                     const Tray& tray) {
    const size_t MIN_HDR = 8 + 2 + 4 + 4; // magic + kdf/cipher + two length fields
    if (wire.size() < MIN_HDR)
        throw std::runtime_error("obiwan_decrypt: wire too short");

    const uint8_t* p = wire.data();

    // Magic
    if (std::memcmp(p, "OBIWAN01", 8) != 0)
        throw std::runtime_error("obiwan_decrypt: bad magic");
    p += 8;

    // KDF and cipher bytes (we only support 0x00/0x00)
    uint8_t kdf_byte    = *p++;
    uint8_t cipher_byte = *p++;
    if (kdf_byte != 0x00)
        throw std::runtime_error("obiwan_decrypt: unsupported KDF byte");
    if (cipher_byte != 0x00)
        throw std::runtime_error("obiwan_decrypt: unsupported cipher byte");

    // CT_classical
    if (wire.data() + wire.size() - p < 4)
        throw std::runtime_error("obiwan_decrypt: truncated ct_classical_len");
    uint32_t ct_classical_len = read_be32(p); p += 4;
    if ((size_t)(wire.data() + wire.size() - p) < ct_classical_len)
        throw std::runtime_error("obiwan_decrypt: truncated ct_classical");
    std::vector<uint8_t> ct_classical(p, p + ct_classical_len);
    p += ct_classical_len;

    // CT_pq
    if (wire.data() + wire.size() - p < 4)
        throw std::runtime_error("obiwan_decrypt: truncated ct_pq_len");
    uint32_t ct_pq_len = read_be32(p); p += 4;
    if ((size_t)(wire.data() + wire.size() - p) < ct_pq_len)
        throw std::runtime_error("obiwan_decrypt: truncated ct_pq");
    std::vector<uint8_t> ct_pq(p, p + ct_pq_len);
    p += ct_pq_len;

    // Remaining = payload (nonce || tag || ct)
    std::vector<uint8_t> payload(p, wire.data() + wire.size());

    if (tray.slots.empty())
        throw std::runtime_error("obiwan_decrypt: tray has no slots");

    // ---- Classical KEM ----
    std::vector<uint8_t> ss_classical;
    if (tray.profile_group == "mceliece+slhdsa") {
        if (tray.slots.size() >= 2 && ct_classical_len > 0) {
            // McEliece Level2+: slot[0] is classical EC
            ec_kem::decaps(tray.slots[0].alg_name, tray.slots[0].sk,
                           ct_classical, ss_classical);
        }
        // McEliece Level1: ct_classical is empty — ss_classical stays empty
    } else {
        // crystals group: slot[0] is EC
        ec_kem::decaps(tray.slots[0].alg_name, tray.slots[0].sk,
                       ct_classical, ss_classical);
    }

    // ---- PQ KEM ----
    // slot[0] for McEliece Level1 (single-slot); slot[1] for all others
    const Slot& kem_pq = (tray.slots.size() == 1) ? tray.slots[0] : tray.slots[1];
    std::vector<uint8_t> ss_pq;
    if (tray.profile_group == "mceliece+slhdsa") {
        mceliece_kem::decaps(kem_pq.alg_name, kem_pq.sk, ct_pq, ss_pq);
    } else {
        kyber_kem::decaps(kyber_kem::level_from_alg(kem_pq.alg_name),
                          kem_pq.sk, ct_pq, ss_pq);
    }

    auto key = derive_key_shake(ss_classical, ss_pq, ct_classical, ct_pq);
    return aes256gcm_decrypt(key.data(), payload);
}

// ---------------------------------------------------------------------------
// Internal: parse tray DB record
// ---------------------------------------------------------------------------

struct TrayRecord {
    uint8_t             enc   = 0;
    std::string         alias;
    uint32_t            flags = 0;
    uint64_t            owner = 0;
    std::vector<uint8_t> blob;
};

static TrayRecord parse_tray_record_full(const std::vector<uint8_t>& record) {
    msgpack::object_handle oh = msgpack::unpack(
        reinterpret_cast<const char*>(record.data()), record.size());
    const msgpack::object& obj = oh.get();

    if (obj.type != msgpack::type::MAP)
        throw std::runtime_error("parse_tray_record_full: expected map");

    TrayRecord r;
    const auto& map = obj.via.map;
    for (uint32_t i = 0; i < map.size; ++i) {
        const auto& kv = map.ptr[i];
        if (kv.key.type != msgpack::type::STR) continue;
        std::string key{kv.key.via.str.ptr, kv.key.via.str.size};

        if (key == "enc") {
            r.enc = static_cast<uint8_t>(kv.val.via.u64);
        } else if (key == "al") {
            r.alias.assign(kv.val.via.str.ptr, kv.val.via.str.size);
        } else if (key == "fl") {
            r.flags = static_cast<uint32_t>(kv.val.via.u64);
        } else if (key == "ow") {
            r.owner = kv.val.via.u64;
        } else if (key == "bl") {
            r.blob.assign(
                reinterpret_cast<const uint8_t*>(kv.val.via.bin.ptr),
                reinterpret_cast<const uint8_t*>(kv.val.via.bin.ptr) + kv.val.via.bin.size);
        }
    }
    return r;
}

static std::vector<uint8_t> tray_to_yaml_bytes(const Tray& tray) {
    std::string s = emit_tray_yaml(tray);
    return {s.begin(), s.end()};
}

static Tray tray_from_yaml_bytes(const std::vector<uint8_t>& bytes) {
    char tmp[] = "/tmp/sarek-tray-XXXXXX";
    int fd = mkstemp(tmp);
    if (fd < 0) throw std::runtime_error("tray_from_yaml_bytes: mkstemp failed");
    if (write(fd, bytes.data(), bytes.size()) != static_cast<ssize_t>(bytes.size())) {
        close(fd); unlink(tmp);
        throw std::runtime_error("tray_from_yaml_bytes: write failed");
    }
    close(fd);
    try {
        Tray t = load_tray_yaml(tmp);
        unlink(tmp);
        return t;
    } catch (...) {
        unlink(tmp);
        throw;
    }
}

// ---------------------------------------------------------------------------
// Internal: pack tray DB record
// ---------------------------------------------------------------------------

static std::vector<uint8_t> pack_tray_record(
        uint8_t enc, const std::string& alias,
        uint32_t flags, uint64_t owner,
        const std::vector<uint8_t>& blob) {
    msgpack::sbuffer buf;
    msgpack::packer<msgpack::sbuffer> pk(buf);

    pk.pack_map(5);
    pk.pack(std::string("enc")); pk.pack_uint8(enc);
    pk.pack(std::string("al"));  pk.pack(alias);
    pk.pack(std::string("fl"));  pk.pack_uint32(flags);
    pk.pack(std::string("ow"));  pk.pack_uint64(owner);
    pk.pack(std::string("bl"));
    pk.pack_bin(static_cast<uint32_t>(blob.size()));
    pk.pack_bin_body(reinterpret_cast<const char*>(blob.data()), blob.size());

    return {reinterpret_cast<const uint8_t*>(buf.data()),
            reinterpret_cast<const uint8_t*>(buf.data()) + buf.size()};
}

// ---------------------------------------------------------------------------
// Internal: UUID string → 16-byte raw bytes
// ---------------------------------------------------------------------------

static std::array<uint8_t, 16> uuid_to_bytes(const std::string& s) {
    std::string hex;
    hex.reserve(32);
    for (char c : s)
        if (c != '-') hex += c;
    if (hex.size() != 32)
        throw std::runtime_error("uuid_to_bytes: invalid UUID '" + s + "'");

    auto from_hex = [](char c) -> uint8_t {
        if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
        if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
        if (c >= 'A' && c <= 'F') return static_cast<uint8_t>(c - 'A' + 10);
        throw std::runtime_error("uuid_to_bytes: invalid hex char");
    };

    std::array<uint8_t, 16> out{};
    for (int i = 0; i < 16; ++i)
        out[i] = static_cast<uint8_t>((from_hex(hex[i*2]) << 4) | from_hex(hex[i*2+1]));
    return out;
}

// ---------------------------------------------------------------------------
// Internal: generate a random unique object_id
// ---------------------------------------------------------------------------

static uint64_t generate_object_id(SarekEnv& env) {
    for (int attempt = 0; attempt < 16; ++attempt) {
        uint64_t id = 0;
        if (RAND_bytes(reinterpret_cast<uint8_t*>(&id), 8) != 1)
            throw std::runtime_error("generate_object_id: RAND_bytes failed");
        id &= ~uint64_t(0); // use all bits
        if (id == 0) continue; // avoid 0
        if (!env.metadata().get(id))
            return id;
    }
    throw std::runtime_error("generate_object_id: failed after 16 attempts");
}

// ---------------------------------------------------------------------------
// UserService
// ---------------------------------------------------------------------------

void create_user(SarekEnv& env,
                 const std::string& username,
                 const std::string& password,
                 uint32_t           flags,
                 const std::vector<std::string>& assertions,
                 uint64_t           user_id,
                 uint8_t            scrypt_n_log2) {
    if (env.user().get(username))
        throw std::runtime_error("create_user: user '" + username + "' already exists");

    UserRecord rec;
    rec.user_id    = user_id;
    rec.pwhash     = password.empty() ? "none" : hash_password(password, scrypt_n_log2);
    rec.flags      = flags;
    rec.assertions = assertions;

    auto bytes = pack_user_record(rec);
    env.user().put(username, bytes);

    get_logger()->info("user.create: username={} flags={:04x}", username, flags);
}

void lock_user(SarekEnv& env, const std::string& username) {
    auto bytes = env.user().get(username);
    if (!bytes)
        throw std::runtime_error("lock_user: user '" + username + "' not found");

    UserRecord rec = unpack_user_record(*bytes);
    rec.flags |= kUserFlagLocked;
    env.user().put(username, pack_user_record(rec));

    get_logger()->warn("user.lock: username={} by={}", username, get_request_user());
}

std::vector<std::pair<std::string, UserRecord>> list_users(SarekEnv& env) {
    std::vector<std::pair<std::string, UserRecord>> result;

    env.user().scan(nullptr,
        [&](const void* k, size_t ksz, const void* v, size_t vsz) -> bool {
            std::string username(reinterpret_cast<const char*>(k), ksz);
            std::vector<uint8_t> record(
                reinterpret_cast<const uint8_t*>(v),
                reinterpret_cast<const uint8_t*>(v) + vsz);
            try {
                result.emplace_back(username, unpack_user_record(record));
            } catch (...) {
                // skip malformed records
            }
            return true;
        });

    return result;
}

void update_user_password(SarekEnv& env,
                          const std::string& username,
                          const std::string& new_password,
                          uint8_t scrypt_n_log2) {
    auto bytes = env.user().get(username);
    if (!bytes)
        throw std::runtime_error("update_user_password: user '" + username + "' not found");

    UserRecord rec = unpack_user_record(*bytes);
    rec.pwhash = hash_password(new_password, scrypt_n_log2);
    env.user().put(username, pack_user_record(rec));

    get_logger()->info("user.changepass: username={} by={}", username, get_request_user());
}

// ---------------------------------------------------------------------------
// TrayService
// ---------------------------------------------------------------------------

void store_tray(SarekEnv& env, const Tray& tray, uint64_t owner_user_id) {
    if (tray.alias.empty())
        throw std::runtime_error("store_tray: tray has no alias");

    // Check alias doesn't already exist
    if (env.tray_alias().get(tray.alias))
        throw std::runtime_error("store_tray: alias '" + tray.alias + "' already exists");

    auto uuid_bytes = uuid_to_bytes(tray.id);
    auto blob       = tray_to_yaml_bytes(tray);
    auto record     = pack_tray_record(0, tray.alias, 0, owner_user_id, blob);

    auto txn = env.begin_txn();
    env.tray().put(uuid_bytes.data(), 16, record.data(), record.size(), txn.get());
    env.tray_alias().put(tray.alias, {uuid_bytes.begin(), uuid_bytes.end()}, txn.get());
    txn->commit();

    get_logger()->info("tray.store: alias={} owner={}", tray.alias, owner_user_id);
}

Tray get_tray_by_id(SarekEnv& env, const void* tray_uuid_16, size_t len) {
    auto bytes = env.tray().get(tray_uuid_16, len);
    if (!bytes)
        throw std::runtime_error("get_tray_by_id: tray not found");

    TrayRecord r = parse_tray_record_full(*bytes);
    if (r.enc != 0)
        throw std::runtime_error("get_tray_by_id: tray is password-encrypted");
    return tray_from_yaml_bytes(r.blob);
}

std::vector<std::string> list_trays_for_user(SarekEnv& env, uint64_t owner_user_id) {
    std::vector<std::string> result;

    env.tray().scan(nullptr,
        [&](const void*, size_t, const void* v, size_t vsz) -> bool {
            std::vector<uint8_t> record(
                reinterpret_cast<const uint8_t*>(v),
                reinterpret_cast<const uint8_t*>(v) + vsz);
            try {
                TrayRecord r = parse_tray_record_full(record);
                if (r.owner == owner_user_id && !r.alias.empty())
                    result.push_back(r.alias);
            } catch (...) {
                // skip malformed records
            }
            return true;
        });

    return result;
}

std::vector<std::string> list_all_trays(SarekEnv& env) {
    std::vector<std::string> result;

    env.tray().scan(nullptr,
        [&](const void*, size_t, const void* v, size_t vsz) -> bool {
            std::vector<uint8_t> record(
                reinterpret_cast<const uint8_t*>(v),
                reinterpret_cast<const uint8_t*>(v) + vsz);
            try {
                TrayRecord r = parse_tray_record_full(record);
                if (!r.alias.empty())
                    result.push_back(r.alias);
            } catch (...) {
                // skip malformed records
            }
            return true;
        });

    return result;
}

// ---------------------------------------------------------------------------
// SecretService
// ---------------------------------------------------------------------------

void create_secret(SarekEnv&                  env,
                   const std::string&          path,
                   const std::vector<uint8_t>& plaintext,
                   const Tray&                 tray,
                   const std::string&          mimetype,
                   uint64_t                    creator_id) {
    validate_path(path);

    uint64_t object_id = generate_object_id(env);

    auto encrypted = obiwan_encrypt(plaintext, tray);

    MetadataRecord meta;
    meta.object_id  = object_id;
    meta.created    = static_cast<int64_t>(std::time(nullptr));
    meta.size       = plaintext.size();
    meta.mimetype   = mimetype;
    meta.tray_id    = tray.id;
    meta.creator_id = creator_id;

    auto meta_bytes = pack_metadata(meta);
    auto id_enc     = encode_uint64(object_id);
    std::vector<uint8_t> id_vec(id_enc.begin(), id_enc.end());

    auto txn = env.begin_txn();
    env.data().put(object_id, encrypted, txn.get());
    env.metadata().put(object_id, meta_bytes, txn.get());
    if (!env.path().put_if_absent(path, id_vec, txn.get())) {
        txn->abort();
        throw std::runtime_error("create_secret: path '" + path + "' already exists");
    }
    txn->commit();

    get_logger()->info("secret.create: path={} object_id={} tray={} size={} mime={}",
                       path, object_id, tray.id, plaintext.size(), mimetype);
}

std::vector<uint8_t> read_secret(
        SarekEnv& env, const std::string& path,
        LruCache<uint64_t, std::vector<uint8_t>>* data_cache) {
    std::string current = path;
    std::unordered_set<std::string> visited;
    visited.insert(current);

    for (;;) {
        auto id_bytes = env.path().get(current);
        if (!id_bytes)
            throw std::runtime_error("read_secret: path '" + current + "' not found");
        if (id_bytes->size() != 8)
            throw std::runtime_error("read_secret: corrupted path entry for '" + current + "'");

        uint64_t object_id = decode_uint64(id_bytes->data());

        // Check cache first. Link nodes are never inserted into data_cache
        // (only real-secret object_ids are cached), so a cache hit here always
        // means we've resolved to an actual data record.
        if (data_cache) {
            auto cached = data_cache->get(object_id);
            if (cached) {
                get_logger()->debug("cache.hit: object_id={}", object_id);
                return *cached;
            }
        }

        auto meta_bytes = env.metadata().get(object_id);
        if (!meta_bytes)
            throw std::runtime_error("read_secret: missing metadata for object " +
                                     std::to_string(object_id));

        MetadataRecord meta = unpack_metadata(*meta_bytes);

        if (!meta.link_path.empty()) {
            if (visited.count(meta.link_path))
                throw std::runtime_error(
                    "read_secret: circular link detected at '" + meta.link_path + "'");
            if (visited.size() > static_cast<size_t>(kMaxLinkDepth))
                throw std::runtime_error("read_secret: link chain too long (>8 hops)");
            visited.insert(meta.link_path);
            current = meta.link_path;
            continue;
        }

        // Actual data — load tray and decrypt
        auto uuid_bytes = uuid_to_bytes(meta.tray_id);
        Tray tray = get_tray_by_id(env, uuid_bytes.data(), 16);

        auto encrypted = env.data().get(object_id);
        if (!encrypted)
            throw std::runtime_error("read_secret: missing data blob for object " +
                                     std::to_string(object_id));

        get_logger()->info("secret.decrypt: path={} object_id={} tray={} user={}",
                           current, object_id, meta.tray_id, get_request_user());

        auto plaintext = obiwan_decrypt(*encrypted, tray);

        if (data_cache) {
            data_cache->put(object_id, plaintext);
            get_logger()->info("cache.put: object_id={} user={}", object_id, get_request_user());
            get_logger()->info("cache.state: entries={}", data_cache->size());
        }

        return plaintext;
    }
}

MetadataRecord read_metadata(SarekEnv& env, const std::string& path) {
    auto id_bytes = env.path().get(path);
    if (!id_bytes)
        throw std::runtime_error("read_metadata: path '" + path + "' not found");
    if (id_bytes->size() != 8)
        throw std::runtime_error("read_metadata: corrupted path entry");

    uint64_t object_id = decode_uint64(id_bytes->data());

    auto meta_bytes = env.metadata().get(object_id);
    if (!meta_bytes)
        throw std::runtime_error("read_metadata: missing metadata for object " +
                                 std::to_string(object_id));

    return unpack_metadata(*meta_bytes);
}

std::vector<std::string> list_secrets(SarekEnv& env, const std::string& prefix) {
    std::vector<std::string> result;

    env.path().scan(nullptr,
        [&](const void* k, size_t ksz, const void*, size_t) -> bool {
            std::string key(reinterpret_cast<const char*>(k), ksz);
            if (prefix.empty() || key.substr(0, prefix.size()) == prefix)
                result.push_back(key);
            return true;
        });

    return result;
}

void create_link(SarekEnv&          env,
                 const std::string& target_path,
                 const std::string& link_path) {
    validate_path(target_path);
    validate_path(link_path);

    // Self-link guard: target and link are the same path.
    if (link_path == target_path)
        throw std::runtime_error(
            "create_link: would create a cycle (self-link '" + link_path + "')");

    // Walk the existing chain from target_path. If any hop resolves to
    // link_path, reject — this would form a cycle.
    {
        std::string cursor = target_path;
        for (int hop = 0; hop <= kMaxLinkDepth; ++hop) {
            auto id_bytes = env.path().get(cursor);
            if (!id_bytes) break;  // target doesn't exist yet, or chain ends — no cycle
            if (id_bytes->size() != 8) break;  // corrupted, don't block creation

            uint64_t oid = decode_uint64(id_bytes->data());
            auto mb = env.metadata().get(oid);
            if (!mb) break;

            MetadataRecord m = unpack_metadata(*mb);
            if (m.link_path.empty()) break;  // reached a real secret, no cycle possible

            if (m.link_path == link_path)
                throw std::runtime_error(
                    "create_link: would create a cycle ('" + link_path +
                    "' already reachable from '" + target_path + "')");
            cursor = m.link_path;
        }
    }

    uint64_t object_id = generate_object_id(env);

    MetadataRecord meta;
    meta.object_id = object_id;
    meta.created   = static_cast<int64_t>(std::time(nullptr));
    meta.size      = 0;
    meta.mimetype  = "application/x-sarek-link";
    meta.link_path = target_path;

    auto meta_bytes = pack_metadata(meta);
    auto id_enc     = encode_uint64(object_id);
    std::vector<uint8_t> id_vec(id_enc.begin(), id_enc.end());

    auto txn = env.begin_txn();
    env.metadata().put(object_id, meta_bytes, txn.get());
    if (!env.path().put_if_absent(link_path, id_vec, txn.get())) {
        txn->abort();
        throw std::runtime_error("create_link: link_path '" + link_path + "' already exists");
    }
    txn->commit();

    get_logger()->info("link.create: link={} -> target={} by={}",
                       link_path, target_path, get_request_user());
}

void delete_link(SarekEnv& env, const std::string& link_path) {
    validate_path(link_path);

    auto id_bytes = env.path().get(link_path);
    if (!id_bytes)
        throw std::runtime_error("delete_link: path '" + link_path + "' not found");
    if (id_bytes->size() != 8)
        throw std::runtime_error("delete_link: corrupted path entry for '" + link_path + "'");

    uint64_t object_id = decode_uint64(id_bytes->data());

    auto meta_bytes = env.metadata().get(object_id);
    if (!meta_bytes)
        throw std::runtime_error("delete_link: missing metadata for object " +
                                 std::to_string(object_id));

    MetadataRecord meta = unpack_metadata(*meta_bytes);
    if (meta.link_path.empty())
        throw std::runtime_error("delete_link: '" + link_path + "' is not a symlink");

    auto txn = env.begin_txn();
    env.path().del(link_path, txn.get());
    env.metadata().del(object_id, txn.get());
    txn->commit();

    get_logger()->info("link.delete: link={} by={}", link_path, get_request_user());
}

// ---------------------------------------------------------------------------
// delete_user (cascade)
// ---------------------------------------------------------------------------

DeleteUserResult delete_user(SarekEnv& env, const std::string& username) {
    // 1. Load the user record to get user_id
    auto user_bytes = env.user().get(username);
    if (!user_bytes)
        throw std::runtime_error("delete_user: user '" + username + "' not found");
    UserRecord user_rec = unpack_user_record(*user_bytes);
    uint64_t user_id = user_rec.user_id;

    // 2. Scan tray table → collect trays owned by this user
    struct TrayEntry {
        std::array<uint8_t, 16> uuid_bytes;
        std::string alias;
        std::string tray_id_str; // hex UUID string for matching metadata
    };
    std::vector<TrayEntry> owned_trays;

    env.tray().scan(nullptr,
        [&](const void* k, size_t ksz, const void* v, size_t vsz) -> bool {
            if (ksz != 16) return true;
            std::vector<uint8_t> record(
                reinterpret_cast<const uint8_t*>(v),
                reinterpret_cast<const uint8_t*>(v) + vsz);
            try {
                TrayRecord r = parse_tray_record_full(record);
                if (r.owner == user_id) {
                    TrayEntry e;
                    std::memcpy(e.uuid_bytes.data(), k, 16);
                    e.alias = r.alias;
                    // Convert 16 raw bytes → canonical UUID string (8-4-4-4-12)
                    char buf[37];
                    const auto* b = reinterpret_cast<const uint8_t*>(k);
                    std::snprintf(buf, sizeof(buf),
                        "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
                        b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);
                    e.tray_id_str = buf;
                    owned_trays.push_back(std::move(e));
                }
            } catch (...) {}
            return true;
        });

    // 3. Build set of tray_id strings to match against metadata
    std::set<std::string> tray_id_set;
    for (const auto& t : owned_trays)
        tray_id_set.insert(t.tray_id_str);

    // 4. Scan metadata → collect object_ids where tray_id matches
    std::vector<uint64_t> oids_to_delete;

    env.metadata().scan(nullptr,
        [&](const void*, size_t, const void* v, size_t vsz) -> bool {
            std::vector<uint8_t> record(
                reinterpret_cast<const uint8_t*>(v),
                reinterpret_cast<const uint8_t*>(v) + vsz);
            try {
                MetadataRecord m = unpack_metadata(record);
                if (tray_id_set.count(m.tray_id))
                    oids_to_delete.push_back(m.object_id);
            } catch (...) {}
            return true;
        });

    // 5. Build set for O(1) lookup
    std::set<uint64_t> oid_set(oids_to_delete.begin(), oids_to_delete.end());

    // 6. Scan path table → collect path strings mapping to deleted object_ids
    std::vector<std::string> paths_to_delete;

    env.path().scan(nullptr,
        [&](const void* k, size_t ksz, const void* v, size_t vsz) -> bool {
            if (vsz == 8) {
                uint64_t oid = decode_uint64(v);
                if (oid_set.count(oid)) {
                    paths_to_delete.emplace_back(
                        reinterpret_cast<const char*>(k), ksz);
                }
            }
            return true;
        });

    // 7. Single transaction: delete everything
    auto txn = env.begin_txn();

    for (const auto& p : paths_to_delete)
        env.path().del(p, txn.get());

    for (uint64_t oid : oid_set) {
        env.metadata().del(oid, txn.get());
        env.data().del(oid, txn.get());
    }

    for (const auto& t : owned_trays) {
        env.tray().del(t.uuid_bytes.data(), 16, txn.get());
        if (!t.alias.empty())
            env.tray_alias().del(t.alias, txn.get());
    }

    env.user().del(username, txn.get());

    txn->commit();

    DeleteUserResult result;
    result.trays_deleted   = static_cast<int>(owned_trays.size());
    result.secrets_deleted = static_cast<int>(oids_to_delete.size());

    get_logger()->warn("user.delete: username={} trays={} secrets={} by={}",
                       username, result.trays_deleted, result.secrets_deleted,
                       get_request_user());

    return result;
}

// ---------------------------------------------------------------------------
// TokenService — manage_token DB helpers
// ---------------------------------------------------------------------------
// Record msgpack format (short keys):
//   "u"  → username  (str)
//   "c"  → created   (int64)
//   "e"  → expiry    (int64)
//   "r"  → revoked   (bool)

static std::vector<uint8_t> pack_token_record(const TokenRecord& t) {
    msgpack::sbuffer buf;
    msgpack::packer<msgpack::sbuffer> pk(buf);
    pk.pack_map(4);
    pk.pack(std::string("u")); pk.pack(t.username);
    pk.pack(std::string("c")); pk.pack_int64(t.created);
    pk.pack(std::string("e")); pk.pack_int64(t.expiry);
    pk.pack(std::string("r")); pk.pack(t.revoked);
    return {reinterpret_cast<const uint8_t*>(buf.data()),
            reinterpret_cast<const uint8_t*>(buf.data()) + buf.size()};
}

static TokenRecord unpack_token_record(const std::string& token_id,
                                        const std::vector<uint8_t>& data) {
    msgpack::object_handle oh = msgpack::unpack(
        reinterpret_cast<const char*>(data.data()), data.size());
    const msgpack::object& obj = oh.get();
    if (obj.type != msgpack::type::MAP)
        throw std::runtime_error("unpack_token_record: expected map");

    TokenRecord t;
    t.token_id = token_id;
    const auto& map = obj.via.map;
    for (uint32_t i = 0; i < map.size; ++i) {
        const auto& kv = map.ptr[i];
        if (kv.key.type != msgpack::type::STR) continue;
        std::string key{kv.key.via.str.ptr, kv.key.via.str.size};
        if (key == "u") {
            t.username.assign(kv.val.via.str.ptr, kv.val.via.str.size);
        } else if (key == "c") {
            t.created = kv.val.as<int64_t>();
        } else if (key == "e") {
            t.expiry = kv.val.as<int64_t>();
        } else if (key == "r") {
            t.revoked = kv.val.as<bool>();
        }
    }
    return t;
}

void register_token(SarekEnv& env,
                    const std::string& token_id,
                    const std::string& username,
                    int64_t created,
                    int64_t expiry) {
    TokenRecord t;
    t.token_id = token_id;
    t.username = username;
    t.created  = created;
    t.expiry   = expiry;
    t.revoked  = false;
    auto packed = pack_token_record(t);
    env.manage_token().put(token_id, packed);
    get_logger()->info("token.register: token_id={} user={}", token_id, username);
}

TokenStatus check_token(SarekEnv& env, const std::string& token_id) {
    auto bytes = env.manage_token().get(token_id);
    if (!bytes) return TokenStatus::NotFound;
    try {
        auto t = unpack_token_record(token_id, *bytes);
        return t.revoked ? TokenStatus::Revoked : TokenStatus::Valid;
    } catch (...) {
        return TokenStatus::NotFound;
    }
}

bool revoke_token(SarekEnv& env, const std::string& token_id) {
    auto bytes = env.manage_token().get(token_id);
    if (!bytes) return false;
    auto t = unpack_token_record(token_id, *bytes);
    t.revoked = true;
    auto packed = pack_token_record(t);
    env.manage_token().put(token_id, packed);
    get_logger()->info("token.revoke: token_id={} user={}", token_id, t.username);
    return true;
}

int revoke_tokens_for_user(SarekEnv& env, const std::string& username) {
    // Collect token_ids for this user via scan
    std::vector<std::string> to_revoke;
    env.manage_token().scan(nullptr,
        [&](const void* k, size_t ksz, const void* v, size_t vsz) -> bool {
            std::string tid(reinterpret_cast<const char*>(k), ksz);
            std::vector<uint8_t> data(
                reinterpret_cast<const uint8_t*>(v),
                reinterpret_cast<const uint8_t*>(v) + vsz);
            try {
                auto t = unpack_token_record(tid, data);
                if (t.username == username && !t.revoked)
                    to_revoke.push_back(tid);
            } catch (...) {}
            return true;
        });

    for (const auto& tid : to_revoke) {
        auto bytes = env.manage_token().get(tid);
        if (!bytes) continue;
        auto t = unpack_token_record(tid, *bytes);
        t.revoked = true;
        env.manage_token().put(tid, pack_token_record(t));
    }
    get_logger()->warn("token.revoke_user: username={} count={}", username, to_revoke.size());
    return static_cast<int>(to_revoke.size());
}

int revoke_all_tokens(SarekEnv& env) {
    std::vector<std::pair<std::string, TokenRecord>> all;
    env.manage_token().scan(nullptr,
        [&](const void* k, size_t ksz, const void* v, size_t vsz) -> bool {
            std::string tid(reinterpret_cast<const char*>(k), ksz);
            std::vector<uint8_t> data(
                reinterpret_cast<const uint8_t*>(v),
                reinterpret_cast<const uint8_t*>(v) + vsz);
            try {
                auto t = unpack_token_record(tid, data);
                if (!t.revoked) all.emplace_back(tid, t);
            } catch (...) {}
            return true;
        });

    for (auto& [tid, t] : all) {
        t.revoked = true;
        env.manage_token().put(tid, pack_token_record(t));
    }
    get_logger()->warn("token.revoke_all: count={}", all.size());
    return static_cast<int>(all.size());
}

std::vector<TokenRecord> list_tokens(SarekEnv& env) {
    std::vector<TokenRecord> result;
    env.manage_token().scan(nullptr,
        [&](const void* k, size_t ksz, const void* v, size_t vsz) -> bool {
            std::string tid(reinterpret_cast<const char*>(k), ksz);
            std::vector<uint8_t> data(
                reinterpret_cast<const uint8_t*>(v),
                reinterpret_cast<const uint8_t*>(v) + vsz);
            try {
                result.push_back(unpack_token_record(tid, data));
            } catch (...) {}
            return true;
        });
    return result;
}

int purge_expired_tokens(SarekEnv& env) {
    int64_t now = static_cast<int64_t>(std::time(nullptr));
    std::vector<std::string> to_delete;

    env.manage_token().scan(nullptr,
        [&](const void* k, size_t ksz, const void* v, size_t vsz) -> bool {
            std::string tid(reinterpret_cast<const char*>(k), ksz);
            std::vector<uint8_t> data(
                reinterpret_cast<const uint8_t*>(v),
                reinterpret_cast<const uint8_t*>(v) + vsz);
            try {
                auto t = unpack_token_record(tid, data);
                if (t.expiry < now)
                    to_delete.push_back(tid);
            } catch (...) {}
            return true;
        });

    for (const auto& tid : to_delete)
        env.manage_token().del(tid);

    if (!to_delete.empty())
        get_logger()->info("token.purge_expired: count={}", to_delete.size());
    return static_cast<int>(to_delete.size());
}

// ---------------------------------------------------------------------------
// WrapService helpers
// ---------------------------------------------------------------------------

static std::string to_base64url(const uint8_t* data, size_t len) {
    std::string b64 = base64_encode(data, len);
    for (char& c : b64) {
        if (c == '+') c = '-';
        else if (c == '/') c = '_';
    }
    while (!b64.empty() && b64.back() == '=') b64.pop_back();
    return b64;
}

static std::vector<uint8_t> from_base64url(const std::string& s) {
    std::string b64 = s;
    for (char& c : b64) {
        if (c == '-') c = '+';
        else if (c == '_') c = '/';
    }
    while (b64.size() % 4 != 0) b64 += '=';
    return base64_decode(b64);
}

// Value format: map{"ui": user_id, "e": expiry_unix, "bl": encrypted_bytes}
static std::vector<uint8_t> pack_wrapped_record(uint64_t user_id, int64_t expiry,
                                                 const std::vector<uint8_t>& blob) {
    msgpack::sbuffer buf;
    msgpack::packer<msgpack::sbuffer> pk(buf);
    pk.pack_map(3);
    pk.pack(std::string("ui")); pk.pack_uint64(user_id);
    pk.pack(std::string("e"));  pk.pack_int64(expiry);
    pk.pack(std::string("bl")); pk.pack_bin(blob.size());
                                pk.pack_bin_body(reinterpret_cast<const char*>(blob.data()), blob.size());
    return {reinterpret_cast<const uint8_t*>(buf.data()),
            reinterpret_cast<const uint8_t*>(buf.data()) + buf.size()};
}

struct WrappedDbValue {
    uint64_t user_id = 0;
    int64_t  expiry  = 0;
    std::vector<uint8_t> blob;
};

static WrappedDbValue unpack_wrapped_record(const std::vector<uint8_t>& data) {
    msgpack::object_handle oh = msgpack::unpack(
        reinterpret_cast<const char*>(data.data()), data.size());
    const msgpack::object& obj = oh.get();
    if (obj.type != msgpack::type::MAP)
        throw std::runtime_error("unpack_wrapped_record: expected map");
    WrappedDbValue v;
    const auto& map = obj.via.map;
    for (uint32_t i = 0; i < map.size; ++i) {
        const auto& kv = map.ptr[i];
        if (kv.key.type != msgpack::type::STR) continue;
        std::string key{kv.key.via.str.ptr, kv.key.via.str.size};
        if (key == "ui") {
            v.user_id = kv.val.as<uint64_t>();
        } else if (key == "e") {
            v.expiry = kv.val.as<int64_t>();
        } else if (key == "bl") {
            v.blob.assign(kv.val.via.bin.ptr,
                          kv.val.via.bin.ptr + kv.val.via.bin.size);
        }
    }
    return v;
}

// ---------------------------------------------------------------------------
// WrapService public functions
// ---------------------------------------------------------------------------

std::string create_wrapped(SarekEnv& env, uint64_t user_id,
                           const std::vector<uint8_t>& plaintext,
                           int64_t ttl_secs) {
    static constexpr int64_t kMinTTL = 600;
    static constexpr int64_t kMaxTTL = 5 * 86400;
    if (ttl_secs < kMinTTL || ttl_secs > kMaxTTL)
        throw std::invalid_argument("wrap: ttl must be between 600s (10m) and 432000s (5d)");

    Tray wrap_tray;
    try {
        wrap_tray = load_tray_by_alias(env, "wrap");
    } catch (const std::exception&) {
        get_logger()->warn("wrap: the 'wrap' tray was not found");
        throw std::runtime_error("wrap: the 'wrap' tray was not found");
    }

    std::array<uint8_t, 16> uuid_key;
    if (RAND_bytes(uuid_key.data(), 16) != 1)
        throw std::runtime_error("wrap: RAND_bytes failed (uuid_key)");

    std::array<uint8_t, 16> token_key;
    if (RAND_bytes(token_key.data(), 16) != 1)
        throw std::runtime_error("wrap: RAND_bytes failed (token_key)");

    int64_t now    = static_cast<int64_t>(std::time(nullptr));
    int64_t expiry = now + ttl_secs;

    auto encrypted = obiwan_encrypt(plaintext, wrap_tray);
    auto packed    = pack_wrapped_record(user_id, expiry, encrypted);

    auto txn = env.begin_txn();
    env.wrapped().put(uuid_key.data(), 16, packed.data(), packed.size(), txn.get());
    env.wrapper_lookup().put(token_key.data(), 16, uuid_key.data(), 16, txn.get());
    txn->commit();

    get_logger()->info("wrap.create: user_id={} expiry={}", user_id, expiry);
    return to_base64url(token_key.data(), 16);
}

std::vector<uint8_t> unwrap(SarekEnv& env, const std::string& base64url_token) {
    auto token_bytes = from_base64url(base64url_token);
    if (token_bytes.size() != 16)
        throw std::runtime_error("unwrap: invalid token length");

    auto uuid_bytes_opt = env.wrapper_lookup().get(token_bytes.data(), 16);
    if (!uuid_bytes_opt)
        throw std::runtime_error("unwrap: token not found");
    if (uuid_bytes_opt->size() != 16)
        throw std::runtime_error("unwrap: corrupt wrapper_lookup record");

    auto packed_opt = env.wrapped().get(uuid_bytes_opt->data(), 16);
    if (!packed_opt)
        throw std::runtime_error("unwrap: wrapped record not found");

    auto wv = unpack_wrapped_record(*packed_opt);

    int64_t now = static_cast<int64_t>(std::time(nullptr));
    if (wv.expiry < now)
        throw std::runtime_error("unwrap: token has expired");

    Tray wrap_tray;
    try {
        wrap_tray = load_tray_by_alias(env, "wrap");
    } catch (const std::exception&) {
        get_logger()->warn("wrap: the 'wrap' tray was not found");
        throw std::runtime_error("wrap: the 'wrap' tray was not found");
    }

    auto plaintext = obiwan_decrypt(wv.blob, wrap_tray);

    auto txn = env.begin_txn();
    env.wrapper_lookup().del(token_bytes.data(), 16, txn.get());
    env.wrapped().del(uuid_bytes_opt->data(), 16, txn.get());
    txn->commit();

    get_logger()->info("wrap.unwrap: user_id={}", wv.user_id);
    return plaintext;
}

int purge_expired_wrapped(SarekEnv& env) {
    int64_t now = static_cast<int64_t>(std::time(nullptr));

    std::vector<std::vector<uint8_t>> expired_uuid_keys;
    env.wrapped().scan(nullptr,
        [&](const void* k, size_t ksz, const void* v, size_t vsz) -> bool {
            try {
                std::vector<uint8_t> packed(
                    reinterpret_cast<const uint8_t*>(v),
                    reinterpret_cast<const uint8_t*>(v) + vsz);
                auto wv = unpack_wrapped_record(packed);
                if (wv.expiry < now) {
                    expired_uuid_keys.push_back(
                        std::vector<uint8_t>(reinterpret_cast<const uint8_t*>(k),
                                             reinterpret_cast<const uint8_t*>(k) + ksz));
                }
            } catch (...) {}
            return true;
        });

    if (expired_uuid_keys.empty()) return 0;

    std::set<std::vector<uint8_t>> expired_set(
        expired_uuid_keys.begin(), expired_uuid_keys.end());

    std::vector<std::vector<uint8_t>> token_keys_to_del;
    env.wrapper_lookup().scan(nullptr,
        [&](const void* k, size_t ksz, const void* v, size_t vsz) -> bool {
            std::vector<uint8_t> uuid_val(
                reinterpret_cast<const uint8_t*>(v),
                reinterpret_cast<const uint8_t*>(v) + vsz);
            if (expired_set.count(uuid_val)) {
                token_keys_to_del.push_back(
                    std::vector<uint8_t>(reinterpret_cast<const uint8_t*>(k),
                                         reinterpret_cast<const uint8_t*>(k) + ksz));
            }
            return true;
        });

    auto txn = env.begin_txn();
    for (const auto& uk : expired_uuid_keys)
        env.wrapped().del(uk.data(), uk.size(), txn.get());
    for (const auto& tk : token_keys_to_del)
        env.wrapper_lookup().del(tk.data(), tk.size(), txn.get());
    txn->commit();

    int n = static_cast<int>(expired_uuid_keys.size());
    get_logger()->info("wrap.purge_expired: count={}", n);
    return n;
}

} // namespace sarek
