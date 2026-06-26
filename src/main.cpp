#include "sigtool/signature_tool.hpp"

#include <exception>
#include <iostream>
#include <string>

namespace {

void print_help() {
    std::cout
        << "sigtool - Lab 5 Classical Digital Signatures\n\n"
        << "Usage:\n"
        << "  sigtool --help\n"
        << "  sigtool version\n"
        << "  sigtool keygen --algo ecdsa-p256 --pub pub.pem --priv priv.pem\n"
        << "  sigtool keygen --algo ecdsa-p384 --pub pub.pem --priv priv.pem\n"
        << "  sigtool keygen --algo rsa-pss-3072 --pub pub.pem --priv priv.pem\n"
        << "  sigtool keyinfo --pub pub.pem\n"
        << "  sigtool sign --algo ecdsa-p256 --priv priv.pem --in message.bin --sig signature.sig\n"
        << "  sigtool verify --algo ecdsa-p256 --pub pub.pem --in message.bin --sig signature.sig\n\n"
        << "Algorithms:\n"
        << "  ecdsa-p256\n"
        << "  ecdsa-p384\n"
        << "  rsa-pss-3072\n";
}

std::string get_arg(int argc, char* argv[], const std::string& name) {
    for (int i = 0; i < argc - 1; ++i) {
        if (argv[i] == name) {
            return argv[i + 1];
        }
    }
    return {};
}

int run_keygen(int argc, char* argv[]) {
    const std::string algo = get_arg(argc, argv, "--algo");
    const std::string pub_path = get_arg(argc, argv, "--pub");
    const std::string priv_path = get_arg(argc, argv, "--priv");

    if (algo.empty() || pub_path.empty() || priv_path.empty()) {
        std::cerr << "ERROR: keygen requires --algo ALGO --pub pub.pem --priv priv.pem\n";
        return 1;
    }

    sigtool::generate_keypair(algo, pub_path, priv_path);
    return 0;
}


int run_sign(int argc, char* argv[]) {
    const std::string algo = get_arg(argc, argv, "--algo");
    const std::string priv_path = get_arg(argc, argv, "--priv");
    const std::string input_path = get_arg(argc, argv, "--in");
    const std::string sig_path = get_arg(argc, argv, "--sig");

    if (algo.empty() || priv_path.empty() || input_path.empty() || sig_path.empty()) {
        std::cerr << "ERROR: sign requires --algo ALGO --priv priv.pem --in message.bin --sig signature.sig\n";
        return 1;
    }

    sigtool::sign_file_detached(algo, priv_path, input_path, sig_path);
    return 0;
}

int run_verify(int argc, char* argv[]) {
    const std::string algo = get_arg(argc, argv, "--algo");
    const std::string pub_path = get_arg(argc, argv, "--pub");
    const std::string input_path = get_arg(argc, argv, "--in");
    const std::string sig_path = get_arg(argc, argv, "--sig");

    if (algo.empty() || pub_path.empty() || input_path.empty() || sig_path.empty()) {
        std::cerr << "ERROR: verify requires --algo ALGO --pub pub.pem --in message.bin --sig signature.sig\n";
        return 1;
    }

    const bool ok = sigtool::verify_file_detached(algo, pub_path, input_path, sig_path);
    return ok ? 0 : 1;
}

int run_keyinfo(int argc, char* argv[]) {
    const std::string pub_path = get_arg(argc, argv, "--pub");

    if (pub_path.empty()) {
        std::cerr << "ERROR: keyinfo requires --pub pub.pem\n";
        return 1;
    }

    sigtool::print_key_info(pub_path);
    return 0;
}

} // namespace

int main(int argc, char* argv[]) {
    try {
        if (argc <= 1) {
            print_help();
            return 0;
        }

        const std::string command = argv[1];

        if (command == "--help" || command == "-h") {
            print_help();
            return 0;
        }

        if (command == "version") {
            std::cout << "sigtool 1.0.0\n";
            std::cout << "OpenSSL-backed ECDSA and RSA-PSS detached signature tool\n";
            return 0;
        }

        if (command == "keygen") {
            return run_keygen(argc, argv);
        }

        if (command == "keyinfo") {
            return run_keyinfo(argc, argv);
        }

        if (command == "sign") {
            return run_sign(argc, argv);
        }

        if (command == "verify") {
            return run_verify(argc, argv);
        }

        std::cerr << "ERROR: unknown command: " << command << "\n";
        std::cerr << "Run: sigtool --help\n";
        return 1;
    } catch (const std::exception& ex) {
        std::cerr << "ERROR: " << ex.what() << "\n";
        return 1;
    }
}
