#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace sarek {

struct UserRecord {
    uint64_t                 user_id    = 0;
    std::string              pwhash;        // "scrypt$n_log2$r$p$b64salt$b64hash"
    uint32_t                 flags      = 0;
    std::vector<std::string> assertions;    // e.g. ["usr:admin", "/*"]
};

static constexpr uint32_t kUserFlagAdmin  = 0x01;
static constexpr uint32_t kUserFlagLocked = 0x02;

// Msgpack serialization for DB storage.
std::vector<uint8_t> pack_user_record(const UserRecord& r);
UserRecord           unpack_user_record(const std::vector<uint8_t>& data);

} // namespace sarek
