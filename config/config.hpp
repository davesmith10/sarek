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
    std::string log_dir;          // log.dir (default: /var/log)

    // TLS (optional — CLI flags override these)
    std::string tls_cert;                    // tls.cert
    std::string tls_key;                     // tls.key

    // Password file paths (optional — TTY prompt used if absent)
    std::string user_password_file;          // user.password-file  (admin password at bootstrap)

    // System tray import (optional — TTY prompt used if absent)
    std::string system_tray_path;            // tray.system
    std::string system_tray_password_file;   // tray.password-file  (system tray decrypt password)
};

// Throws std::runtime_error  if file is missing or a required field is absent.
// Throws std::invalid_argument if max-data-node-sz has an unrecognised suffix.
SarekConfig load_config(const std::string& path);

// Exposed for testing.
size_t parse_size_str(const std::string& s);

} // namespace sarek
