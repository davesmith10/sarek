#include "config/config.hpp"
#include "db/db.hpp"
#include "bootstrap/bootstrap.hpp"
#include "http/http.hpp"
#include "log/log.hpp"

#include <csignal>
#include <cstdlib>
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
        << "  --config <path>   Path to sarek.yml (default: /etc/sarek.yml)\n"
        << "  --cert   <path>   TLS certificate PEM (enables HTTPS)\n"
        << "  --key    <path>   TLS private key PEM  (enables HTTPS)\n"
        << "  --dev             Plain HTTP, no TLS (development only)\n"
        << "  --help            Show this message\n"
        << "\n"
        << "TLS is enabled when both --cert and --key are provided.\n"
        << "In --dev mode TLS is suppressed regardless of --cert/--key.\n";
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main(int argc, char* argv[]) {
    std::string config_path = "/etc/sarek.yml";
    std::string cert_path;
    std::string key_path;
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
        } else if (arg == "--cert" && i + 1 < argc) {
            cert_path = argv[++i];
        } else if (arg == "--key" && i + 1 < argc) {
            key_path = argv[++i];
        } else {
            std::cerr << "Unknown option: " << arg << "\n";
            print_usage(argv[0]);
            return 1;
        }
    }

    if (dev_mode) {
        cert_path.clear();
        key_path.clear();
    }

    if ((!cert_path.empty()) != (!key_path.empty())) {
        std::cerr << "Error: --cert and --key must be supplied together.\n";
        return 1;
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

    // ── Initialize logging ────────────────────────────────────────────────────
    sarek::init_logging("/var/log/sarek/sarek.log", dev_mode);
    auto log = sarek::get_logger();

    log->info("config loaded from {}", config_path);
    log->info("db_path={} port={}", cfg.db_path, cfg.http_port);

    // ── Bootstrap or open DB ──────────────────────────────────────────────────
    std::unique_ptr<sarek::SarekEnv> env;
    try {
        if (sarek::needs_bootstrap(cfg)) {
            log->info("first-run bootstrap — creating database and system trays");
            env = sarek::run_bootstrap_interactive(cfg);
            log->info("bootstrap complete");
        } else {
            env = std::make_unique<sarek::SarekEnv>(cfg.db_path);
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
