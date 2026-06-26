#include "sigtool/file_utils.hpp"

#include <filesystem>
#include <fstream>
#include <stdexcept>

namespace sigtool {

std::vector<uint8_t> read_binary_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw std::runtime_error("cannot open input file: " + path);
    }

    in.seekg(0, std::ios::end);
    const std::streamsize size = in.tellg();
    in.seekg(0, std::ios::beg);

    if (size < 0) {
        throw std::runtime_error("cannot determine file size: " + path);
    }

    std::vector<uint8_t> data(static_cast<size_t>(size));

    if (size > 0) {
        in.read(reinterpret_cast<char*>(data.data()), size);
        if (!in) {
            throw std::runtime_error("cannot read file: " + path);
        }
    }

    return data;
}

void write_binary_file(const std::string& path, const std::vector<uint8_t>& data) {
    const std::filesystem::path p(path);
    if (!p.parent_path().empty()) {
        std::filesystem::create_directories(p.parent_path());
    }

    std::ofstream out(path, std::ios::binary);
    if (!out) {
        throw std::runtime_error("cannot open output file: " + path);
    }

    if (!data.empty()) {
        out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    }
}

void write_text_file(const std::string& path, const std::string& text) {
    const std::filesystem::path p(path);
    if (!p.parent_path().empty()) {
        std::filesystem::create_directories(p.parent_path());
    }

    std::ofstream out(path);
    if (!out) {
        throw std::runtime_error("cannot open output file: " + path);
    }

    out << text;
}

} // namespace sigtool
