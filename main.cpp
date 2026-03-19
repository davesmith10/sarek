#include "config/config.hpp"
#include "db/db.hpp"
#include "bootstrap/bootstrap.hpp"
#include "http/http.hpp"
#include "log/log.hpp"

#include <crystals/crystals.hpp>

#include <yaml-cpp/yaml.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <csignal>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>

// ---------------------------------------------------------------------------
// Usage
// ---------------------------------------------------------------------------

static void print_usage(const char* argv0) {
    std::cerr
        << "Usage: " << argv0 << " [OPTIONS]\n"
        << "\n"
        << "Options:\n"
        << "  --config             <path>   Path to sarek.yml (default: /etc/sarek.yml)\n"
        << "  --cert               <path>   TLS certificate PEM (enables HTTPS, overrides config)\n"
        << "  --key                <path>   TLS private key PEM  (enables HTTPS, overrides config)\n"
        << "  --password-file      <path>   Read bootstrap admin password from file (overrides config)\n"
        << "  --tray-password-file <path>   Read system tray decrypt password from file (overrides config)\n"
        << "  --dev                         Plain HTTP, no TLS (development only)\n"
        << "  --help                        Show this message\n"
        << "\n"
        << "TLS is enabled when both --cert and --key are provided (CLI or config).\n"
        << "In --dev mode TLS is suppressed regardless of --cert/--key.\n";
}

// ---------------------------------------------------------------------------
// Helper: read first line of a file
// ---------------------------------------------------------------------------

static std::string read_file_first_line(const std::string& path) {
    std::ifstream f(path);
    if (!f) throw std::runtime_error("cannot open file: " + path);
    std::string line;
    std::getline(f, line);
    if (!line.empty() && line.back() == '\r') line.pop_back();
    if (line.empty()) throw std::runtime_error("file is empty: " + path);
    return line;
}

// ---------------------------------------------------------------------------
// Helper: load system tray from file into the env keyring
// Used on subsequent boots (DB already exists).
// ---------------------------------------------------------------------------

static void init_system_tray_keyring(sarek::SarekEnv& env,
                                      const sarek::SarekConfig& cfg,
                                      const std::string& tray_pw_file_override) {
    // Tray path: CLI-supplied via config, else prompt
    std::string tray_path = cfg.system_tray_path;
    if (tray_path.empty()) {
        std::cout << "Please input path to the system tray: " << std::flush;
        std::getline(std::cin, tray_path);
        if (tray_path.empty())
            throw std::runtime_error("No system tray path provided");
    }

    // Peek at the YAML type field to decide whether we need a password
    YAML::Node root;
    try {
        root = YAML::LoadFile(tray_path);
    } catch (const YAML::Exception& e) {
        throw std::runtime_error(
            "init_system_tray_keyring: cannot load tray file '" +
            tray_path + "': " + e.what());
    }
    std::string type;
    if (root["type"]) type = root["type"].as<std::string>();

    // Tray password (only for secure-tray)
    char tray_pw_buf[256] = {};
    std::string tray_pw_str;
    const char* tray_pw  = nullptr;
    size_t      tray_pwl = 0;

    if (type == "secure-tray") {
        // Priority: CLI --tray-password-file > config tray.password-file > TTY prompt
        const std::string& pw_file = !tray_pw_file_override.empty()
            ? tray_pw_file_override
            : cfg.system_tray_password_file;

        if (!pw_file.empty()) {
            tray_pw_str = read_file_first_line(pw_file);
            tray_pw  = tray_pw_str.c_str();
            tray_pwl = tray_pw_str.size();
        } else {
            if (EVP_read_pw_string(tray_pw_buf, sizeof(tray_pw_buf),
                                   "Tray is protected. Please provide the password: ", 0) != 0)
                throw std::runtime_error("Tray password input failed");
            tray_pw  = tray_pw_buf;
            tray_pwl = std::strlen(tray_pw_buf);
        }
    }

    Tray sys = sarek::import_system_tray(tray_path, tray_pw, tray_pwl);
    OPENSSL_cleanse(tray_pw_buf, sizeof(tray_pw_buf));

    auto sys_plain = tray_mp::pack(sys);
    auto blob = sarek::KeyringBlob::store(
        "sarek:system-tray", sys_plain.data(), sys_plain.size());
    env.set_system_tray_keyring(std::move(blob));
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main(int argc, char* argv[]) {
    std::string config_path = "/etc/sarek.yml";
    std::string cert_path_cli;
    std::string key_path_cli;
    std::string password_file;
    std::string tray_pw_file;
    bool        dev_mode = false;

    // ── Parse arguments ──────────────────────────────────────────────────────
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            print_usage(argv[0]);
            return 0;
        } else if (arg == "--dev") {
            dev_mode = true;
        } else if (arg == "--config" && i + 1 < argc) {
            config_path = argv[++i];
        } else if (arg == "--password-file" && i + 1 < argc) {
            password_file = argv[++i];
        } else if (arg == "--tray-password-file" && i + 1 < argc) {
            tray_pw_file = argv[++i];
        } else if (arg == "--cert" && i + 1 < argc) {
            cert_path_cli = argv[++i];
        } else if (arg == "--key" && i + 1 < argc) {
            key_path_cli = argv[++i];
        } else {
            std::cerr << "Unknown option: " << arg << "\n";
            print_usage(argv[0]);
            return 1;
        }
    }

    // ── Load configuration ────────────────────────────────────────────────────
    sarek::SarekConfig cfg;
    try {
        cfg = sarek::load_config(config_path);
    } catch (const std::exception& e) {
        std::cerr << "Failed to load config '" << config_path << "': "
                  << e.what() << "\n";
        return 1;
    }

    // ── Resolve TLS paths: CLI flags override config ──────────────────────────
    std::string cert_path = cert_path_cli.empty() ? cfg.tls_cert : cert_path_cli;
    std::string key_path  = key_path_cli.empty()  ? cfg.tls_key  : key_path_cli;

    if (dev_mode) {
        cert_path.clear();
        key_path.clear();
    }

    if ((!cert_path.empty()) != (!key_path.empty())) {
        std::cerr << "Error: --cert and --key must be supplied together.\n";
        return 1;
    }

    // ── Initialize logging ────────────────────────────────────────────────────
    sarek::init_logging(cfg.log_dir + "/sarek/sarek.log", dev_mode);
    auto log = sarek::get_logger();

    log->info("config loaded from {}", config_path);
    log->info("db_path={} port={}", cfg.db_path, cfg.http_port);

    // ── Bootstrap or open DB ──────────────────────────────────────────────────
    std::unique_ptr<sarek::SarekEnv> env;
    try {
        if (sarek::needs_bootstrap(cfg)) {
            log->info("first-run bootstrap — creating database and system trays");

            // Override config password-file fields with CLI flags if provided
            sarek::SarekConfig boot_cfg = cfg;
            if (!password_file.empty()) boot_cfg.user_password_file = password_file;
            if (!tray_pw_file.empty())  boot_cfg.system_tray_password_file = tray_pw_file;

            env = sarek::run_bootstrap_interactive(boot_cfg);
            log->info("bootstrap complete");
        } else {
            log->info("opening existing database");
            env = std::make_unique<sarek::SarekEnv>(cfg.db_path);

            // Re-populate keyring with system tray on every boot
            log->info("loading system tray into keyring");
            init_system_tray_keyring(*env, cfg, tray_pw_file);
            log->info("system tray loaded into keyring");
        }
    } catch (const std::exception& e) {
        log->error("startup failed: {}", e.what());
        return 1;
    }

    // ── Install signal handlers ───────────────────────────────────────────────
    {
        struct sigaction sa{};
        sa.sa_handler = [](int) { sarek::request_shutdown(); };
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = 0;
        sigaction(SIGINT,  &sa, nullptr);
        sigaction(SIGTERM, &sa, nullptr);
    }

    // ── Start server ──────────────────────────────────────────────────────────
    if (cert_path.empty()) {
        log->info("starting plain-HTTP server on port {} (development mode)", cfg.http_port);
    } else {
        log->info("starting HTTPS server on port {}", cfg.http_port);
    }

    try {
        sarek::run_server(*env, cfg, cert_path, key_path);
    } catch (const std::exception& e) {
        log->error("server error: {}", e.what());
        return 1;
    }

    log->info("shutting down — closing database");
    env.reset();   // explicit BDB close before process exit
    log->info("shutdown complete");
    return 0;
}
