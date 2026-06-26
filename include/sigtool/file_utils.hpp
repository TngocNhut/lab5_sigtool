#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace sigtool {

std::vector<uint8_t> read_binary_file(const std::string& path);
void write_binary_file(const std::string& path, const std::vector<uint8_t>& data);
void write_text_file(const std::string& path, const std::string& text);

} // namespace sigtool
