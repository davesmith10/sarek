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

static void test_load_config_new_optional_fields() {
    // Create real temp files so path-readability checks pass.
    std::string cert_path   = write_tmp("cert");
    std::string key_path    = write_tmp("key");
    std::string pwfile_path = write_tmp("pw");
    std::string tray_path   = write_tmp("tray");
    std::string traypw_path = write_tmp("traypw");

    std::string yaml =
        "---\n"
        "defaults:\n"
        "  cache-ttl: 86400\n"
        "  max-data-node-sz: 1mb\n"
        "db:\n"
        "  path: /var/lib/sarek\n"
        "http:\n"
        "  port: 8080\n"
        "user:\n"
        "  adminuser: admin\n"
        "  password-file: " + pwfile_path + "\n"
        "tls:\n"
        "  cert: " + cert_path + "\n"
        "  key:  " + key_path + "\n"
        "tray:\n"
        "  system: " + tray_path + "\n"
        "  password-file: " + traypw_path + "\n";

    std::string p = write_tmp(yaml);
    sarek::SarekConfig cfg = sarek::load_config(p);
    std::remove(p.c_str());
    std::remove(cert_path.c_str());
    std::remove(key_path.c_str());
    std::remove(pwfile_path.c_str());
    std::remove(tray_path.c_str());
    std::remove(traypw_path.c_str());

    assert(cfg.tls_cert                  == cert_path);
    assert(cfg.tls_key                   == key_path);
    assert(cfg.user_password_file        == pwfile_path);
    assert(cfg.system_tray_path          == tray_path);
    assert(cfg.system_tray_password_file == traypw_path);

    std::puts("load_config (new optional fields): OK");
}

static void test_load_config_new_fields_absent() {
    // When new optional fields are absent, they should be empty strings.
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

    assert(cfg.tls_cert.empty());
    assert(cfg.tls_key.empty());
    assert(cfg.user_password_file.empty());
    assert(cfg.system_tray_path.empty());
    assert(cfg.system_tray_password_file.empty());

    std::puts("load_config (new fields absent → empty): OK");
}

static void test_load_config_path_validation_throws() {
    const std::string bad = "/tmp/sarek_nonexistent_path_xyz987.pem";

    // Each yaml has exactly one path field set to a nonexistent file.
    // user.password-file is in the same user: block as adminuser to avoid duplicate keys.
    struct Case { std::string label; std::string yaml; };
    Case cases[] = {
        {"tray.system",
         "---\ndefaults:\n  cache-ttl: 3600\n  max-data-node-sz: 1mb\n"
         "db:\n  path: /var/lib/sarek\nhttp:\n  port: 8443\n"
         "user:\n  adminuser: admin\n"
         "tray:\n  system: " + bad + "\n"},

        {"tls.cert",
         "---\ndefaults:\n  cache-ttl: 3600\n  max-data-node-sz: 1mb\n"
         "db:\n  path: /var/lib/sarek\nhttp:\n  port: 8443\n"
         "user:\n  adminuser: admin\n"
         "tls:\n  cert: " + bad + "\n"},

        {"user.password-file",
         "---\ndefaults:\n  cache-ttl: 3600\n  max-data-node-sz: 1mb\n"
         "db:\n  path: /var/lib/sarek\nhttp:\n  port: 8443\n"
         "user:\n  adminuser: admin\n  password-file: " + bad + "\n"},

        {"tls.key",
         "---\ndefaults:\n  cache-ttl: 3600\n  max-data-node-sz: 1mb\n"
         "db:\n  path: /var/lib/sarek\nhttp:\n  port: 8443\n"
         "user:\n  adminuser: admin\n"
         "tls:\n  key: " + bad + "\n"},

        {"tray.password-file",
         "---\ndefaults:\n  cache-ttl: 3600\n  max-data-node-sz: 1mb\n"
         "db:\n  path: /var/lib/sarek\nhttp:\n  port: 8443\n"
         "user:\n  adminuser: admin\n"
         "tray:\n  password-file: " + bad + "\n"},
    };

    for (auto& c : cases) {
        std::string p = write_tmp(c.yaml);
        bool threw = false;
        try {
            sarek::load_config(p);
        } catch (const std::runtime_error&) {
            threw = true;
        }
        std::remove(p.c_str());
        assert(threw && ("nonexistent path should throw for: " + c.label).c_str());
    }
    std::puts("load_config (path validation throws on bad paths): OK");
}

static void test_load_config_all_paths_empty_no_throw() {
    // All optional path fields absent → no throw.
    const char* yaml = R"yaml(---
defaults:
  cache-ttl: 3600
  max-data-node-sz: 1mb
db:
  path: /var/lib/sarek
http:
  port: 8443
user:
  adminuser: admin
)yaml";

    std::string p = write_tmp(yaml);
    bool threw = false;
    try {
        sarek::load_config(p);
    } catch (...) {
        threw = true;
    }
    std::remove(p.c_str());
    assert(!threw && "empty optional path fields should not throw");
    std::puts("load_config (empty path fields no throw): OK");
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
    test_load_config_new_optional_fields();
    test_load_config_new_fields_absent();
    test_load_config_missing_field();
    test_load_config_bad_suffix();
    test_load_config_missing_file();
    test_load_config_path_validation_throws();
    test_load_config_all_paths_empty_no_throw();

    std::puts("\nAll config tests passed.");
    return 0;
}
