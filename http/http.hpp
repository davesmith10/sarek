#pragma once

#include "db/db.hpp"
#include "config/config.hpp"
#include "cache/lru_cache.hpp"

#include <string>
#include <vector>

namespace sarek {

// Start the HTTPS server (blocks until stop() is called or process exits).
// If cert_path is empty, starts plain HTTP (development only).
// Configures TLS with X25519MLKEM768:X25519 group preference when using TLS.
void run_server(SarekEnv&          env,
                const SarekConfig& cfg,
                const std::string& cert_path = "",
                const std::string& key_path  = "");

// Signal the active server to stop its listen loop.
// Safe to call from a signal handler; no-op if no server is running.
void request_shutdown();

} // namespace sarek
