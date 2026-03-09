#pragma once
#include <spdlog/spdlog.h>
#include <memory>
#include <string>

namespace sarek {

// Call once at startup from main.cpp.
// log_file: path to rotating log file (e.g. "/var/log/sarek/sarek.log")
// console:  also print to stderr (useful in --dev mode)
void init_logging(const std::string& log_file, bool console = false);

std::shared_ptr<spdlog::logger> get_logger();

// Thread-local user context — set in HTTP handlers, read by vault/db layer
void set_request_user(const std::string& username);
void clear_request_user();
const std::string& get_request_user(); // returns "" if not set

} // namespace sarek
