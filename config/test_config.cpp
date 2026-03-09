#include "config.hpp"

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <stdexcept>
#include <string>

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
static std::string write_tmp(const std::string& content) {
    // Use mkstemp-style: write to a fixed tmp name for simplicity.
    static int counter = 0;
    std::string p = "/tmp/sarek_test_" + std::to_string(++counter) + ".yml";
    std::ofstream f(p);
    if (!f) throw std::runtime_error("cannot open " + p);
    f << content;
    return p;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
static void test_parse_size_str() {
    using sarek::parse_size_str;

    assert(parse_size_str("1024")  == 1024);
    assert(parse_size_str("1024b") == 1024);
    assert(parse_size_str("1kb")   == 1024);
    assert(parse_size_str("1KB")   == 1024);
    assert(parse_size_str("1mb")   == 1048576);
    assert(parse_size_str("2MB")   == 2 * 1048576);
    assert(parse_size_str("1gb")   == 1073741824ULL);

    bool threw = false;
    try { parse_size_str("1tb"); } catch (const std::invalid_argument&) { threw = true; }
    assert(threw && "bad suffix should throw");

    threw = false;
    try { parse_size_str(""); } catch (const std::invalid_argument&) { threw = true; }
    assert(threw && "empty string should throw");

    std::puts("parse_size_str: OK");
}

static void test_load_config_happy_path() {
    const char* yaml = R"yaml(---
defaults:
  cache-ttl: 86400
  max-data-node-sz: 1mb
db:
  path: /var/lib/sarek
http:
  port: 8080
user:
  adminuser: admin
)yaml";

    std::string p = write_tmp(yaml);
    sarek::SarekConfig cfg = sarek::load_config(p);
    std::remove(p.c_str());

    assert(cfg.cache_ttl_secs   == 86400);
    assert(cfg.max_data_node_sz == 1048576);
    assert(cfg.db_path          == "/var/lib/sarek");
    assert(cfg.http_port        == 8080);
    assert(cfg.admin_user       == "admin");
    assert(cfg.log_dir          == "/var/log");   // default when not specified

    std::puts("load_config (happy path): OK");
}

static void test_load_config_log_dir() {
    const char* yaml = R"yaml(---
defaults:
  cache-ttl: 300
  max-data-node-sz: 1mb
db:
  path: /var/lib/sarek
http:
  port: 8443
user:
  adminuser: admin
log:
  dir: /tmp/sarek-logs
)yaml";

    std::string p = write_tmp(yaml);
    sarek::SarekConfig cfg = sarek::load_config(p);
    std::remove(p.c_str());

    assert(cfg.log_dir == "/tmp/sarek-logs");

    std::puts("load_config (log.dir): OK");
}

static void test_load_config_missing_field() {
    // Missing http.port
    const char* yaml = R"yaml(---
defaults:
  cache-ttl: 86400
  max-data-node-sz: 1mb
db:
  path: /var/lib/sarek
user:
  adminuser: admin
)yaml";

    std::string p = write_tmp(yaml);
    bool threw = false;
    try {
        sarek::load_config(p);
    } catch (const std::runtime_error&) {
        threw = true;
    }
    std::remove(p.c_str());
    assert(threw && "missing field should throw runtime_error");
    std::puts("load_config (missing field): OK");
}

static void test_load_config_bad_suffix() {
    const char* yaml = R"yaml(---
defaults:
  cache-ttl: 86400
  max-data-node-sz: 1tb
db:
  path: /var/lib/sarek
http:
  port: 8080
user:
  adminuser: admin
)yaml";

    std::string p = write_tmp(yaml);
    bool threw = false;
    try {
        sarek::load_config(p);
    } catch (const std::invalid_argument&) {
        threw = true;
    }
    std::remove(p.c_str());
    assert(threw && "bad size suffix should throw invalid_argument");
    std::puts("load_config (bad size suffix): OK");
}

static void test_load_config_missing_file() {
    bool threw = false;
    try {
        sarek::load_config("/tmp/sarek_no_such_file_abc123.yml");
    } catch (const std::runtime_error&) {
        threw = true;
    }
    assert(threw && "missing file should throw runtime_error");
    std::puts("load_config (missing file): OK");
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main() {
    test_parse_size_str();
    test_load_config_happy_path();
    test_load_config_log_dir();
    test_load_config_missing_field();
    test_load_config_bad_suffix();
    test_load_config_missing_file();

    std::puts("\nAll config tests passed.");
    return 0;
}
