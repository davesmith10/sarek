#include "bootstrap/user_record.hpp"

#include <msgpack.hpp>
#include <stdexcept>

namespace sarek {

std::vector<uint8_t> pack_user_record(const UserRecord& r) {
    msgpack::sbuffer buf;
    msgpack::packer<msgpack::sbuffer> pk(buf);

    pk.pack_map(4);

    pk.pack(std::string("uid")); pk.pack_uint64(r.user_id);
    pk.pack(std::string("ph"));  pk.pack(r.pwhash);
    pk.pack(std::string("fl"));  pk.pack_uint32(r.flags);
    pk.pack(std::string("as"));
    pk.pack_array(static_cast<uint32_t>(r.assertions.size()));
    for (const auto& a : r.assertions) pk.pack(a);

    return {reinterpret_cast<const uint8_t*>(buf.data()),
            reinterpret_cast<const uint8_t*>(buf.data()) + buf.size()};
}

UserRecord unpack_user_record(const std::vector<uint8_t>& data) {
    msgpack::object_handle oh = msgpack::unpack(
        reinterpret_cast<const char*>(data.data()), data.size());
    const msgpack::object& obj = oh.get();

    if (obj.type != msgpack::type::MAP)
        throw std::runtime_error("unpack_user_record: expected map");

    UserRecord r;
    const auto& map = obj.via.map;
    for (uint32_t i = 0; i < map.size; ++i) {
        const auto& kv = map.ptr[i];
        if (kv.key.type != msgpack::type::STR) continue;
        std::string key{kv.key.via.str.ptr, kv.key.via.str.size};

        if (key == "uid") {
            if (kv.val.type != msgpack::type::POSITIVE_INTEGER)
                throw std::runtime_error("unpack_user_record: 'uid' must be uint");
            r.user_id = kv.val.via.u64;
        } else if (key == "ph") {
            if (kv.val.type != msgpack::type::STR)
                throw std::runtime_error("unpack_user_record: 'ph' must be str");
            r.pwhash = {kv.val.via.str.ptr, kv.val.via.str.size};
        } else if (key == "fl") {
            if (kv.val.type != msgpack::type::POSITIVE_INTEGER)
                throw std::runtime_error("unpack_user_record: 'fl' must be uint");
            r.flags = static_cast<uint32_t>(kv.val.via.u64);
        } else if (key == "as") {
            if (kv.val.type != msgpack::type::ARRAY)
                throw std::runtime_error("unpack_user_record: 'as' must be array");
            const auto& arr = kv.val.via.array;
            for (uint32_t j = 0; j < arr.size; ++j) {
                if (arr.ptr[j].type != msgpack::type::STR)
                    throw std::runtime_error("unpack_user_record: assertion must be str");
                r.assertions.emplace_back(arr.ptr[j].via.str.ptr,
                                          arr.ptr[j].via.str.size);
            }
        }
    }
    return r;
}

} // namespace sarek
