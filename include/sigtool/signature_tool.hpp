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

void sign_file_detached(
    const std::string& algo,
    const std::string& private_pem_path,
    const std::string& input_path,
    const std::string& signature_path
);

bool verify_file_detached(
    const std::string& algo,
    const std::string& public_pem_path,
    const std::string& input_path,
    const std::string& signature_path
);

void run_signature_benchmark_csv(
    const std::string& out_csv
);

} // namespace sigtool
