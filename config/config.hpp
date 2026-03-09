#pragma once

#include <cstddef>
#include <string>
#include <vector>

namespace sarek {

struct SarekConfig {
    int         cache_ttl_secs;   // defaults.cache-ttl (seconds)
    size_t      max_data_node_sz; // defaults.max-data-node-sz (bytes)
    std::string db_path;          // db.path
    int         http_port;        // http.port
    std::string admin_user;       // user.adminuser
    std::vector<std::string> trusted_proxies; // http.trusted-proxies (optional)
};

// Throws std::runtime_error  if file is missing or a required field is absent.
// Throws std::invalid_argument if max-data-node-sz has an unrecognised suffix.
SarekConfig load_config(const std::string& path);

// Exposed for testing.
size_t parse_size_str(const std::string& s);

} // namespace sarek
