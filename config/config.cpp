#include "config.hpp"

#include <yaml-cpp/yaml.h>

#include <algorithm>
#include <cctype>
#include <fstream>
#include <stdexcept>
#include <string>

namespace sarek {

// ---------------------------------------------------------------------------
// check_file_readable
// ---------------------------------------------------------------------------
static void check_file_readable(const std::string& label, const std::string& path) {
    if (path.empty()) return;
    std::ifstream f(path);
    if (!f.good()) {
        throw std::runtime_error("config: " + label + " path not readable: " + path);
    }
}

// ---------------------------------------------------------------------------
// parse_size_str
// ---------------------------------------------------------------------------
// Accepts:  "1mb", "512kb", "2gb", "1024" (bare integer = bytes)
// Suffixes: b / kb / mb / gb  (case-insensitive)
size_t parse_size_str(const std::string& s) {
    if (s.empty())
        throw std::invalid_argument("parse_size_str: empty string");

    // Split into numeric prefix and suffix.
    size_t i = 0;
    while (i < s.size() && (std::isdigit(static_cast<unsigned char>(s[i])) || s[i] == '.'))
        ++i;

    if (i == 0)
        throw std::invalid_argument("parse_size_str: no numeric prefix in '" + s + "'");

    double num = std::stod(s.substr(0, i));

    std::string suffix = s.substr(i);
    std::transform(suffix.begin(), suffix.end(), suffix.begin(),
                   [](unsigned char c){ return std::tolower(c); });

    size_t multiplier = 1;
    if (suffix.empty() || suffix == "b") {
        multiplier = 1;
    } else if (suffix == "kb") {
        multiplier = 1024ULL;
    } else if (suffix == "mb") {
        multiplier = 1024ULL * 1024;
    } else if (suffix == "gb") {
        multiplier = 1024ULL * 1024 * 1024;
    } else {
        throw std::invalid_argument("parse_size_str: unrecognised suffix '" + suffix + "'");
    }

    return static_cast<size_t>(num * static_cast<double>(multiplier));
}

// ---------------------------------------------------------------------------
// load_config
// ---------------------------------------------------------------------------
SarekConfig load_config(const std::string& path) {
    YAML::Node root;
    try {
        root = YAML::LoadFile(path);
    } catch (const YAML::Exception& e) {
        throw std::runtime_error("load_config: cannot load '" + path + "': " + e.what());
    }

    auto require = [&](const char* section, const char* key) -> YAML::Node {
        if (!root[section] || !root[section][key]) {
            throw std::runtime_error(
                std::string("load_config: missing required field '") +
                section + "." + key + "' in " + path);
        }
        return root[section][key];
    };

    SarekConfig cfg;

    cfg.cache_ttl_secs   = require("defaults", "cache-ttl").as<int>();
    cfg.max_data_node_sz = parse_size_str(require("defaults", "max-data-node-sz").as<std::string>());
    cfg.db_path          = require("db",   "path").as<std::string>();
    cfg.http_port        = require("http", "port").as<int>();
    cfg.admin_user       = require("user", "adminuser").as<std::string>();

    if (root["http"] && root["http"]["trusted-proxies"]) {
        for (const auto& node : root["http"]["trusted-proxies"])
            cfg.trusted_proxies.push_back(node.as<std::string>());
    }

    cfg.log_dir = "/var/log";
    if (root["log"] && root["log"]["dir"])
        cfg.log_dir = root["log"]["dir"].as<std::string>();
    // Strip trailing slashes so path construction is always clean.
    while (cfg.log_dir.size() > 1 && cfg.log_dir.back() == '/')
        cfg.log_dir.pop_back();

    // TLS (optional)
    if (root["tls"] && root["tls"]["cert"])
        cfg.tls_cert = root["tls"]["cert"].as<std::string>();
    if (root["tls"] && root["tls"]["key"])
        cfg.tls_key = root["tls"]["key"].as<std::string>();

    // user.password-file (optional)
    if (root["user"] && root["user"]["password-file"])
        cfg.user_password_file = root["user"]["password-file"].as<std::string>();

    // tray section (optional)
    if (root["tray"] && root["tray"]["system"])
        cfg.system_tray_path = root["tray"]["system"].as<std::string>();
    if (root["tray"] && root["tray"]["password-file"])
        cfg.system_tray_password_file = root["tray"]["password-file"].as<std::string>();

    check_file_readable("tls.cert",           cfg.tls_cert);
    check_file_readable("tls.key",            cfg.tls_key);
    check_file_readable("user.password-file", cfg.user_password_file);
    check_file_readable("tray.system",        cfg.system_tray_path);
    check_file_readable("tray.password-file", cfg.system_tray_password_file);

    return cfg;
}

} // namespace sarek
