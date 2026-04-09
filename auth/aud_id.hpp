#pragma once
#include <string>

namespace sarek {

// Load the audience ID from path.
// If the file does not exist, generate a new UUID v4, write it to path
// (mode 0600, parent directories created if needed), then return the UUID.
// The UUID is formatted as "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".
// Throws std::runtime_error on any I/O or crypto failure.
std::string load_or_create_aud_id(const std::string& path);

} // namespace sarek
