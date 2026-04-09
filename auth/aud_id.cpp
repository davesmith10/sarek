#include "auth/aud_id.hpp"

#include <openssl/rand.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>

namespace sarek {

namespace {

static std::string gen_uuid_v4_str() {
    uint8_t b[16];
    if (RAND_bytes(b, 16) != 1)
        throw std::runtime_error("load_or_create_aud_id: RAND_bytes failed");
    b[6] = (b[6] & 0x0f) | 0x40;  // version 4
    b[8] = (b[8] & 0x3f) | 0x80;  // variant 10xx
    char buf[37];
    std::snprintf(buf, sizeof(buf),
        "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        b[0],  b[1],  b[2],  b[3],
        b[4],  b[5],  b[6],  b[7],
        b[8],  b[9],  b[10], b[11],
        b[12], b[13], b[14], b[15]);
    return buf;
}

} // anonymous namespace

std::string load_or_create_aud_id(const std::string& path) {
    // Try to read existing file.
    {
        std::ifstream f(path);
        if (f.good()) {
            std::string line;
            std::getline(f, line);
            if (!line.empty() && line.back() == '\r') line.pop_back();
            if (!line.empty()) return line;
        }
    }

    // File absent or empty — generate a new UUID.
    std::string uuid = gen_uuid_v4_str();

    // Create parent directories.
    std::filesystem::path p(path);
    if (p.has_parent_path()) {
        std::error_code ec;
        std::filesystem::create_directories(p.parent_path(), ec);
        if (ec)
            throw std::runtime_error(
                "load_or_create_aud_id: cannot create directory '" +
                p.parent_path().string() + "': " + ec.message());
    }

    // Write with O_CREAT|O_EXCL so a race results in re-reading rather than
    // overwriting a UUID another process just created.
    int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) {
        if (errno == EEXIST) {
            // Lost the race — read what the winner wrote.
            std::ifstream f2(path);
            std::string line;
            std::getline(f2, line);
            if (!line.empty() && line.back() == '\r') line.pop_back();
            if (!line.empty()) return line;
        }
        throw std::runtime_error(
            std::string("load_or_create_aud_id: cannot create '") +
            path + "': " + std::strerror(errno));
    }

    // Write UUID + newline.
    std::string content = uuid + "\n";
    ssize_t written = ::write(fd, content.c_str(), content.size());
    ::close(fd);
    if (written != static_cast<ssize_t>(content.size()))
        throw std::runtime_error(
            "load_or_create_aud_id: write failed for '" + path + "'");

    return uuid;
}

} // namespace sarek
