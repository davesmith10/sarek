#include "log/log.hpp"

#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>

#include <filesystem>
#include <memory>
#include <string>
#include <vector>

namespace sarek {

static std::shared_ptr<spdlog::logger> g_logger;

void init_logging(const std::string& log_file, bool console) {
    // Ensure log directory exists
    std::filesystem::path p(log_file);
    if (p.has_parent_path())
        std::filesystem::create_directories(p.parent_path());

    std::vector<spdlog::sink_ptr> sinks;

    // Rotating file: 10 MB, 5 rotations
    sinks.push_back(std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
        log_file, 10 * 1024 * 1024, 5));

    if (console)
        sinks.push_back(std::make_shared<spdlog::sinks::stderr_color_sink_mt>(spdlog::color_mode::automatic));

    g_logger = std::make_shared<spdlog::logger>("sarek", sinks.begin(), sinks.end());
    g_logger->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%^%-5l%$] %v");
    g_logger->set_level(spdlog::level::debug);
    g_logger->flush_on(spdlog::level::info);

    spdlog::register_logger(g_logger);
}

std::shared_ptr<spdlog::logger> get_logger() {
    if (!g_logger) {
        // Fallback: stderr logger for tests and early startup (before init_logging).
        g_logger = spdlog::stderr_color_mt("sarek");
        g_logger->set_level(spdlog::level::warn);
    }
    return g_logger;
}

namespace {
    thread_local std::string tl_user;
}

void set_request_user(const std::string& username) {
    tl_user = username;
}

void clear_request_user() {
    tl_user.clear();
}

const std::string& get_request_user() {
    return tl_user;
}

} // namespace sarek
