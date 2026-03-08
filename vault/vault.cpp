#include "vault/vault.hpp"
#include "bootstrap/user_record.hpp"

#include <crystals/ec_kem.hpp>
#include <crystals/kyber_kem.hpp>
#include <crystals/kdf.hpp>
#include <crystals/symmetric.hpp>
#include <crystals/tray_pack.hpp>

#include <msgpack.hpp>

#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

namespace sarek {

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
    const bool has_link = !m.link_path.empty();
    const uint32_t map_size = has_link ? 6 : 5;

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
    if (tray.slots.size() < 2)
        throw std::runtime_error("obiwan_encrypt: tray must have at least 2 slots");

    const Slot& kem_classical = tray.slots[0];
    const Slot& kem_pq        = tray.slots[1];

    // Encapsulate
    std::vector<uint8_t> ct_classical, ss_classical;
    ec_kem::encaps(kem_classical.alg_name, kem_classical.pk, ct_classical, ss_classical);

    std::vector<uint8_t> ct_pq, ss_pq;
    kyber_kem::encaps(kyber_kem::level_from_alg(kem_pq.alg_name),
                      kem_pq.pk, ct_pq, ss_pq);

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

    if (tray.slots.size() < 2)
        throw std::runtime_error("obiwan_decrypt: tray must have at least 2 slots");

    const Slot& kem_classical = tray.slots[0];
    const Slot& kem_pq        = tray.slots[1];

    std::vector<uint8_t> ss_classical;
    ec_kem::decaps(kem_classical.alg_name, kem_classical.sk, ct_classical, ss_classical);

    std::vector<uint8_t> ss_pq;
    kyber_kem::decaps(kyber_kem::level_from_alg(kem_pq.alg_name),
                      kem_pq.sk, ct_pq, ss_pq);

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
    rec.pwhash     = hash_password(password, scrypt_n_log2);
    rec.flags      = flags;
    rec.assertions = assertions;

    auto bytes = pack_user_record(rec);
    env.user().put(username, bytes);
}

void lock_user(SarekEnv& env, const std::string& username) {
    auto bytes = env.user().get(username);
    if (!bytes)
        throw std::runtime_error("lock_user: user '" + username + "' not found");

    UserRecord rec = unpack_user_record(*bytes);
    rec.flags |= kUserFlagLocked;
    env.user().put(username, pack_user_record(rec));
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
    auto blob       = tray_mp::pack(tray);
    auto record     = pack_tray_record(0, tray.alias, 0, owner_user_id, blob);

    auto txn = env.begin_txn();
    env.tray().put(uuid_bytes.data(), 16, record.data(), record.size(), txn.get());
    env.tray_alias().put(tray.alias, {uuid_bytes.begin(), uuid_bytes.end()}, txn.get());
    txn->commit();
}

Tray get_tray_by_id(SarekEnv& env, const void* tray_uuid_16, size_t len) {
    auto bytes = env.tray().get(tray_uuid_16, len);
    if (!bytes)
        throw std::runtime_error("get_tray_by_id: tray not found");

    TrayRecord r = parse_tray_record_full(*bytes);
    if (r.enc != 0)
        throw std::runtime_error("get_tray_by_id: tray is password-encrypted");
    return tray_mp::unpack(r.blob);
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

// ---------------------------------------------------------------------------
// SecretService
// ---------------------------------------------------------------------------

void create_secret(SarekEnv&                  env,
                   const std::string&          path,
                   const std::vector<uint8_t>& plaintext,
                   const Tray&                 tray,
                   const std::string&          mimetype) {
    validate_path(path);

    if (env.path().get(path))
        throw std::runtime_error("create_secret: path '" + path + "' already exists");

    uint64_t object_id = generate_object_id(env);

    auto encrypted = obiwan_encrypt(plaintext, tray);

    MetadataRecord meta;
    meta.object_id = object_id;
    meta.created   = static_cast<int64_t>(std::time(nullptr));
    meta.size      = plaintext.size();
    meta.mimetype  = mimetype;
    meta.tray_id   = tray.id;

    auto meta_bytes = pack_metadata(meta);
    auto id_enc     = encode_uint64(object_id);

    auto txn = env.begin_txn();
    env.data().put(object_id, encrypted, txn.get());
    env.metadata().put(object_id, meta_bytes, txn.get());
    {
        std::vector<uint8_t> id_vec(id_enc.begin(), id_enc.end());
        env.path().put(path, id_vec, txn.get());
    }
    txn->commit();
}

std::vector<uint8_t> read_secret(
        SarekEnv& env, const std::string& path,
        LruCache<uint64_t, std::vector<uint8_t>>* data_cache) {
    std::string current = path;

    for (int hop = 0; hop <= 8; ++hop) {
        auto id_bytes = env.path().get(current);
        if (!id_bytes)
            throw std::runtime_error("read_secret: path '" + current + "' not found");
        if (id_bytes->size() != 8)
            throw std::runtime_error("read_secret: corrupted path entry for '" + current + "'");

        uint64_t object_id = decode_uint64(id_bytes->data());

        // Check cache first
        if (data_cache) {
            auto cached = data_cache->get(object_id);
            if (cached) return *cached;
        }

        auto meta_bytes = env.metadata().get(object_id);
        if (!meta_bytes)
            throw std::runtime_error("read_secret: missing metadata for object " +
                                     std::to_string(object_id));

        MetadataRecord meta = unpack_metadata(*meta_bytes);

        if (!meta.link_path.empty()) {
            if (hop == 8)
                throw std::runtime_error("read_secret: link chain too long (>8 hops)");
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

        auto plaintext = obiwan_decrypt(*encrypted, tray);

        if (data_cache)
            data_cache->put(object_id, plaintext);

        return plaintext;
    }

    throw std::runtime_error("read_secret: link chain too long (>8 hops)");
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

    if (env.path().get(link_path))
        throw std::runtime_error("create_link: link_path '" + link_path + "' already exists");

    uint64_t object_id = generate_object_id(env);

    MetadataRecord meta;
    meta.object_id = object_id;
    meta.created   = static_cast<int64_t>(std::time(nullptr));
    meta.size      = 0;
    meta.mimetype  = "application/x-sarek-link";
    meta.link_path = target_path;

    auto meta_bytes = pack_metadata(meta);
    auto id_enc     = encode_uint64(object_id);

    auto txn = env.begin_txn();
    env.metadata().put(object_id, meta_bytes, txn.get());
    {
        std::vector<uint8_t> id_vec(id_enc.begin(), id_enc.end());
        env.path().put(link_path, id_vec, txn.get());
    }
    txn->commit();
}

} // namespace sarek
