#pragma once

#include <string>

namespace sigtool {

bool is_supported_algo(const std::string& algo);

void generate_keypair(
    const std::string& algo,
    const std::string& public_pem_path,
    const std::string& private_pem_path
);

void print_key_info(
    const std::string& public_pem_path
);

} // namespace sigtool
