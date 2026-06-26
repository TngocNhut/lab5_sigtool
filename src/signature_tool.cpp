#include "sigtool/signature_tool.hpp"

#include <openssl/bio.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include <filesystem>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>

namespace sigtool {

namespace {

struct EvpPkeyDeleter {
    void operator()(EVP_PKEY* p) const {
        EVP_PKEY_free(p);
    }
};

struct EvpPkeyCtxDeleter {
    void operator()(EVP_PKEY_CTX* p) const {
        EVP_PKEY_CTX_free(p);
    }
};

using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>;
using EvpPkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, EvpPkeyCtxDeleter>;

std::string openssl_error_string() {
    char buf[256] = {};
    const unsigned long err = ERR_get_error();

    if (err == 0) {
        return "unknown OpenSSL error";
    }

    ERR_error_string_n(err, buf, sizeof(buf));
    return std::string(buf);
}

void ensure_ok(int rc, const std::string& what) {
    if (rc != 1) {
        throw std::runtime_error(what + ": " + openssl_error_string());
    }
}

int nid_for_ec_algo(const std::string& algo) {
    if (algo == "ecdsa-p256") {
        return NID_X9_62_prime256v1;
    }

    if (algo == "ecdsa-p384") {
        return NID_secp384r1;
    }

    return 0;
}

EvpPkeyPtr generate_ec_key(const std::string& algo) {
    const int nid = nid_for_ec_algo(algo);
    if (nid == 0) {
        throw std::runtime_error("unsupported ECDSA algorithm: " + algo);
    }

    EvpPkeyCtxPtr ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr));
    if (!ctx) {
        throw std::runtime_error("EVP_PKEY_CTX_new_id EC failed");
    }

    ensure_ok(EVP_PKEY_keygen_init(ctx.get()), "EC keygen init failed");
    ensure_ok(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx.get(), nid), "set EC curve failed");
    ensure_ok(EVP_PKEY_CTX_set_ec_param_enc(ctx.get(), OPENSSL_EC_NAMED_CURVE), "set EC named curve failed");

    EVP_PKEY* raw = nullptr;
    ensure_ok(EVP_PKEY_keygen(ctx.get(), &raw), "EC keygen failed");

    return EvpPkeyPtr(raw);
}

EvpPkeyPtr generate_rsa_pss_key() {
    EvpPkeyCtxPtr ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr));
    if (!ctx) {
        throw std::runtime_error("EVP_PKEY_CTX_new_id RSA failed");
    }

    ensure_ok(EVP_PKEY_keygen_init(ctx.get()), "RSA keygen init failed");
    ensure_ok(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), 3072), "set RSA bits failed");

    BIGNUM* e = BN_new();
    if (!e) {
        throw std::runtime_error("BN_new failed");
    }

    if (BN_set_word(e, RSA_F4) != 1) {
        BN_free(e);
        throw std::runtime_error("BN_set_word failed");
    }

    const int exp_rc = EVP_PKEY_CTX_set_rsa_keygen_pubexp(ctx.get(), e);
    BN_free(e);
    ensure_ok(exp_rc, "set RSA public exponent failed");

    EVP_PKEY* raw = nullptr;
    ensure_ok(EVP_PKEY_keygen(ctx.get(), &raw), "RSA keygen failed");

    return EvpPkeyPtr(raw);
}

void save_private_key_pem(EVP_PKEY* key, const std::string& path) {
    const std::filesystem::path p(path);
    if (!p.parent_path().empty()) {
        std::filesystem::create_directories(p.parent_path());
    }

    FILE* f = fopen(path.c_str(), "wb");
    if (!f) {
        throw std::runtime_error("cannot open private key path: " + path);
    }

    const int rc = PEM_write_PrivateKey(f, key, nullptr, nullptr, 0, nullptr, nullptr);
    fclose(f);

    ensure_ok(rc, "write private key PEM failed");
}

void save_public_key_pem(EVP_PKEY* key, const std::string& path) {
    const std::filesystem::path p(path);
    if (!p.parent_path().empty()) {
        std::filesystem::create_directories(p.parent_path());
    }

    FILE* f = fopen(path.c_str(), "wb");
    if (!f) {
        throw std::runtime_error("cannot open public key path: " + path);
    }

    const int rc = PEM_write_PUBKEY(f, key);
    fclose(f);

    ensure_ok(rc, "write public key PEM failed");
}

void save_private_key_der(EVP_PKEY* key, const std::string& path) {
    FILE* f = fopen(path.c_str(), "wb");
    if (!f) {
        throw std::runtime_error("cannot open private DER path: " + path);
    }

    const int rc = i2d_PrivateKey_fp(f, key);
    fclose(f);

    ensure_ok(rc, "write private key DER failed");
}

void save_public_key_der(EVP_PKEY* key, const std::string& path) {
    FILE* f = fopen(path.c_str(), "wb");
    if (!f) {
        throw std::runtime_error("cannot open public DER path: " + path);
    }

    const int rc = i2d_PUBKEY_fp(f, key);
    fclose(f);

    ensure_ok(rc, "write public key DER failed");
}

std::string replace_extension(const std::string& path, const std::string& ext) {
    std::filesystem::path p(path);
    p.replace_extension(ext);
    return p.string();
}

EvpPkeyPtr load_public_key_pem(const std::string& path) {
    FILE* f = fopen(path.c_str(), "rb");
    if (!f) {
        throw std::runtime_error("cannot open public key: " + path);
    }

    EVP_PKEY* raw = PEM_read_PUBKEY(f, nullptr, nullptr, nullptr);
    fclose(f);

    if (!raw) {
        throw std::runtime_error("cannot parse public key PEM: " + path);
    }

    return EvpPkeyPtr(raw);
}

} // namespace

bool is_supported_algo(const std::string& algo) {
    return algo == "ecdsa-p256" ||
           algo == "ecdsa-p384" ||
           algo == "rsa-pss-3072";
}

void generate_keypair(
    const std::string& algo,
    const std::string& public_pem_path,
    const std::string& private_pem_path
) {
    if (!is_supported_algo(algo)) {
        throw std::runtime_error("unsupported algorithm: " + algo);
    }

    EvpPkeyPtr key;

    if (algo == "ecdsa-p256" || algo == "ecdsa-p384") {
        key = generate_ec_key(algo);
    } else if (algo == "rsa-pss-3072") {
        key = generate_rsa_pss_key();
    }

    save_public_key_pem(key.get(), public_pem_path);
    save_private_key_pem(key.get(), private_pem_path);

    const std::string public_der_path = replace_extension(public_pem_path, ".der");
    const std::string private_der_path = replace_extension(private_pem_path, ".der");

    save_public_key_der(key.get(), public_der_path);
    save_private_key_der(key.get(), private_der_path);

    std::cout << "[OK] Generated key pair\n";
    std::cout << "[OK] Algorithm: " << algo << "\n";
    std::cout << "[OK] Public PEM: " << public_pem_path << "\n";
    std::cout << "[OK] Private PEM: " << private_pem_path << "\n";
    std::cout << "[OK] Public DER: " << public_der_path << "\n";
    std::cout << "[OK] Private DER: " << private_der_path << "\n";

    if (algo == "rsa-pss-3072") {
        std::cout << "[INFO] RSA modulus: 3072 bits\n";
        std::cout << "[INFO] RSA public exponent: 65537\n";
        std::cout << "[INFO] Intended padding: RSA-PSS\n";
        std::cout << "[INFO] Hash: SHA-256\n";
        std::cout << "[INFO] PSS salt length: hashLen = 32 bytes\n";
    }

    if (algo == "ecdsa-p256") {
        std::cout << "[INFO] Curve: secp256r1 / prime256v1 / P-256\n";
        std::cout << "[INFO] Hash: SHA-256\n";
    }

    if (algo == "ecdsa-p384") {
        std::cout << "[INFO] Curve: secp384r1 / P-384\n";
        std::cout << "[INFO] Hash: SHA-384 recommended, SHA-256 also supported in this lab\n";
    }
}

void print_key_info(const std::string& public_pem_path) {
    EvpPkeyPtr key = load_public_key_pem(public_pem_path);

    const int type = EVP_PKEY_base_id(key.get());

    std::cout << "[OK] Public key: " << public_pem_path << "\n";

    if (type == EVP_PKEY_EC) {
        const EC_KEY* ec = EVP_PKEY_get0_EC_KEY(key.get());
        if (!ec) {
            throw std::runtime_error("cannot access EC key");
        }

        const EC_GROUP* group = EC_KEY_get0_group(ec);
        const int nid = EC_GROUP_get_curve_name(group);

        std::cout << "[OK] Key type: ECDSA / EC\n";
        std::cout << "[OK] Curve NID: " << nid << "\n";

        if (nid == NID_X9_62_prime256v1) {
            std::cout << "[OK] Curve: secp256r1 / P-256\n";
            std::cout << "[OK] Approx security: 128-bit\n";
        } else if (nid == NID_secp384r1) {
            std::cout << "[OK] Curve: secp384r1 / P-384\n";
            std::cout << "[OK] Approx security: 192-bit\n";
        } else {
            std::cout << "[WARN] Unknown EC curve\n";
        }

        return;
    }

    if (type == EVP_PKEY_RSA || type == EVP_PKEY_RSA_PSS) {
        const RSA* rsa = EVP_PKEY_get0_RSA(key.get());
        if (!rsa) {
            throw std::runtime_error("cannot access RSA key");
        }

        std::cout << "[OK] Key type: RSA / RSA-PSS capable\n";
        std::cout << "[OK] Modulus bits: " << RSA_bits(rsa) << "\n";
        std::cout << "[OK] Required modulus bits: 3072\n";

        if (RSA_bits(rsa) >= 3072) {
            std::cout << "[OK] RSA modulus requirement satisfied\n";
        } else {
            std::cout << "[FAIL] RSA modulus too small\n";
        }

        return;
    }

    std::cout << "[WARN] Unsupported public key type\n";
}

} // namespace sigtool

#include "sigtool/file_utils.hpp"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include <vector>

namespace sigtool {

namespace {

struct EvpMdCtxDeleter2 {
    void operator()(EVP_MD_CTX* p) const {
        EVP_MD_CTX_free(p);
    }
};

using EvpMdCtxPtr2 = std::unique_ptr<EVP_MD_CTX, EvpMdCtxDeleter2>;

struct EvpPkeyDeleter2 {
    void operator()(EVP_PKEY* p) const {
        EVP_PKEY_free(p);
    }
};

using EvpPkeyPtr2 = std::unique_ptr<EVP_PKEY, EvpPkeyDeleter2>;

std::string openssl_error_string2() {
    char buf[256] = {};
    const unsigned long err = ERR_get_error();

    if (err == 0) {
        return "unknown OpenSSL error";
    }

    ERR_error_string_n(err, buf, sizeof(buf));
    return std::string(buf);
}

void ensure_ok2(int rc, const std::string& what) {
    if (rc != 1) {
        throw std::runtime_error(what + ": " + openssl_error_string2());
    }
}

const EVP_MD* digest_for_signature_algo(const std::string& algo) {
    if (algo == "ecdsa-p384") {
        return EVP_sha384();
    }

    return EVP_sha256();
}

EvpPkeyPtr2 load_private_key_for_signing(const std::string& path) {
    FILE* f = fopen(path.c_str(), "rb");
    if (!f) {
        throw std::runtime_error("cannot open private key: " + path);
    }

    EVP_PKEY* raw = PEM_read_PrivateKey(f, nullptr, nullptr, nullptr);
    fclose(f);

    if (!raw) {
        throw std::runtime_error("cannot parse private key PEM: " + path);
    }

    return EvpPkeyPtr2(raw);
}

EvpPkeyPtr2 load_public_key_for_verifying(const std::string& path) {
    FILE* f = fopen(path.c_str(), "rb");
    if (!f) {
        throw std::runtime_error("cannot open public key: " + path);
    }

    EVP_PKEY* raw = PEM_read_PUBKEY(f, nullptr, nullptr, nullptr);
    fclose(f);

    if (!raw) {
        throw std::runtime_error("cannot parse public key PEM: " + path);
    }

    return EvpPkeyPtr2(raw);
}

void configure_rsa_pss_if_needed(EVP_PKEY_CTX* pctx, const std::string& algo) {
    if (algo != "rsa-pss-3072") {
        return;
    }

    ensure_ok2(EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING),
               "set RSA-PSS padding failed");

    ensure_ok2(EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, EVP_sha256()),
               "set RSA-PSS MGF1 SHA-256 failed");

    ensure_ok2(EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, 32),
               "set RSA-PSS salt length failed");
}

std::string digest_name_for_algo(const std::string& algo) {
    if (algo == "ecdsa-p384") {
        return "SHA-384";
    }

    return "SHA-256";
}

} // namespace

void sign_file_detached(
    const std::string& algo,
    const std::string& private_pem_path,
    const std::string& input_path,
    const std::string& signature_path
) {
    if (!is_supported_algo(algo)) {
        throw std::runtime_error("unsupported algorithm: " + algo);
    }

    const std::vector<uint8_t> message = read_binary_file(input_path);
    EvpPkeyPtr2 key = load_private_key_for_signing(private_pem_path);

    EvpMdCtxPtr2 mdctx(EVP_MD_CTX_new());
    if (!mdctx) {
        throw std::runtime_error("EVP_MD_CTX_new failed");
    }

    EVP_PKEY_CTX* pctx = nullptr;

    ensure_ok2(
        EVP_DigestSignInit(
            mdctx.get(),
            &pctx,
            digest_for_signature_algo(algo),
            nullptr,
            key.get()
        ),
        "EVP_DigestSignInit failed"
    );

    configure_rsa_pss_if_needed(pctx, algo);

    ensure_ok2(
        EVP_DigestSignUpdate(mdctx.get(), message.data(), message.size()),
        "EVP_DigestSignUpdate failed"
    );

    size_t sig_len = 0;

    ensure_ok2(
        EVP_DigestSignFinal(mdctx.get(), nullptr, &sig_len),
        "EVP_DigestSignFinal length query failed"
    );

    std::vector<uint8_t> signature(sig_len);

    ensure_ok2(
        EVP_DigestSignFinal(mdctx.get(), signature.data(), &sig_len),
        "EVP_DigestSignFinal failed"
    );

    signature.resize(sig_len);
    write_binary_file(signature_path, signature);

    std::cout << "[OK] Detached signature created\n";
    std::cout << "[OK] Algorithm: " << algo << "\n";
    std::cout << "[OK] Digest: " << digest_name_for_algo(algo) << "\n";
    std::cout << "[OK] Input file: " << input_path << "\n";
    std::cout << "[OK] Input size: " << message.size() << " bytes\n";
    std::cout << "[OK] Private key: " << private_pem_path << "\n";
    std::cout << "[OK] Signature file: " << signature_path << "\n";
    std::cout << "[OK] Signature size: " << signature.size() << " bytes\n";

    if (algo == "rsa-pss-3072") {
        std::cout << "[INFO] RSA-PSS salt length: 32 bytes\n";
        std::cout << "[INFO] RSA-PSS MGF1: SHA-256\n";
    }
}

bool verify_file_detached(
    const std::string& algo,
    const std::string& public_pem_path,
    const std::string& input_path,
    const std::string& signature_path
) {
    if (!is_supported_algo(algo)) {
        throw std::runtime_error("unsupported algorithm: " + algo);
    }

    const std::vector<uint8_t> message = read_binary_file(input_path);
    const std::vector<uint8_t> signature = read_binary_file(signature_path);
    EvpPkeyPtr2 key = load_public_key_for_verifying(public_pem_path);

    EvpMdCtxPtr2 mdctx(EVP_MD_CTX_new());
    if (!mdctx) {
        throw std::runtime_error("EVP_MD_CTX_new failed");
    }

    EVP_PKEY_CTX* pctx = nullptr;

    ensure_ok2(
        EVP_DigestVerifyInit(
            mdctx.get(),
            &pctx,
            digest_for_signature_algo(algo),
            nullptr,
            key.get()
        ),
        "EVP_DigestVerifyInit failed"
    );

    configure_rsa_pss_if_needed(pctx, algo);

    ensure_ok2(
        EVP_DigestVerifyUpdate(mdctx.get(), message.data(), message.size()),
        "EVP_DigestVerifyUpdate failed"
    );

    const int rc = EVP_DigestVerifyFinal(
        mdctx.get(),
        signature.data(),
        signature.size()
    );

    if (rc == 1) {
        std::cout << "[OK] Signature verification succeeded\n";
        std::cout << "[OK] Algorithm: " << algo << "\n";
        std::cout << "[OK] Digest: " << digest_name_for_algo(algo) << "\n";
        std::cout << "[OK] Input file: " << input_path << "\n";
        std::cout << "[OK] Public key: " << public_pem_path << "\n";
        std::cout << "[OK] Signature file: " << signature_path << "\n";
        std::cout << "[OK] Signature size: " << signature.size() << " bytes\n";
        return true;
    }

    if (rc == 0) {
        std::cout << "[FAIL] Signature verification failed\n";
        std::cout << "[INFO] Algorithm: " << algo << "\n";
        std::cout << "[INFO] Input file: " << input_path << "\n";
        std::cout << "[INFO] Public key: " << public_pem_path << "\n";
        std::cout << "[INFO] Signature file: " << signature_path << "\n";
        return false;
    }

    throw std::runtime_error("EVP_DigestVerifyFinal error: " + openssl_error_string2());
}

} // namespace sigtool

#include <chrono>
#include <fstream>
#include <iomanip>

namespace sigtool {

namespace {

template <typename Fn>
double measure_ms_bench(Fn&& fn) {
    const auto start = std::chrono::steady_clock::now();
    fn();
    const auto end = std::chrono::steady_clock::now();

    return std::chrono::duration<double, std::milli>(end - start).count();
}

std::vector<uint8_t> bench_message_bytes() {
    std::vector<uint8_t> msg(1024);

    for (size_t i = 0; i < msg.size(); ++i) {
        msg[i] = static_cast<uint8_t>(i & 0xff);
    }

    return msg;
}

} // namespace

void run_signature_benchmark_csv(const std::string& out_csv) {
    const std::filesystem::path out_path(out_csv);

    if (!out_path.parent_path().empty()) {
        std::filesystem::create_directories(out_path.parent_path());
    }

    const std::filesystem::path tmp_dir = out_path.parent_path() / "tmp_sig_bench";
    std::filesystem::create_directories(tmp_dir);

    const std::filesystem::path msg_path = tmp_dir / "message_1k.bin";
    write_binary_file(msg_path.string(), bench_message_bytes());

    std::ofstream out(out_csv);
    if (!out) {
        throw std::runtime_error("cannot open benchmark CSV: " + out_csv);
    }

    out << "algorithm,operation,iterations,total_ms,avg_ms,ops_per_sec,signature_size_bytes\n";

    const std::vector<std::string> algos = {
        "ecdsa-p256",
        "ecdsa-p384",
        "rsa-pss-3072"
    };

    std::cout << "[INFO] Signature benchmark output CSV: " << out_csv << "\n";

    for (const std::string& algo : algos) {
        const std::filesystem::path pub_path = tmp_dir / (algo + "_pub.pem");
        const std::filesystem::path priv_path = tmp_dir / (algo + "_priv.pem");
        const std::filesystem::path sig_path = tmp_dir / (algo + ".sig");

        const size_t keygen_iters = (algo == "rsa-pss-3072") ? 5 : 100;
        const double keygen_total = measure_ms_bench([&]() {
            for (size_t i = 0; i < keygen_iters; ++i) {
                const std::filesystem::path pub_i = tmp_dir / (algo + "_pub_" + std::to_string(i) + ".pem");
                const std::filesystem::path priv_i = tmp_dir / (algo + "_priv_" + std::to_string(i) + ".pem");
                generate_keypair(algo, pub_i.string(), priv_i.string());
            }
        });

        out << algo << ",keygen," << keygen_iters << ","
            << std::fixed << std::setprecision(6)
            << keygen_total << ","
            << (keygen_total / static_cast<double>(keygen_iters)) << ","
            << (1000.0 * static_cast<double>(keygen_iters) / keygen_total) << ","
            << 0 << "\n";

        std::cout << "[OK] " << algo
                  << " keygen avg_ms="
                  << (keygen_total / static_cast<double>(keygen_iters))
                  << "\n";

        generate_keypair(algo, pub_path.string(), priv_path.string());

        const size_t sign_iters = (algo == "rsa-pss-3072") ? 100 : 1000;
        const double sign_total = measure_ms_bench([&]() {
            for (size_t i = 0; i < sign_iters; ++i) {
                sign_file_detached(algo, priv_path.string(), msg_path.string(), sig_path.string());
            }
        });

        const size_t sig_size = std::filesystem::file_size(sig_path);

        out << algo << ",sign," << sign_iters << ","
            << sign_total << ","
            << (sign_total / static_cast<double>(sign_iters)) << ","
            << (1000.0 * static_cast<double>(sign_iters) / sign_total) << ","
            << sig_size << "\n";

        std::cout << "[OK] " << algo
                  << " sign avg_ms="
                  << (sign_total / static_cast<double>(sign_iters))
                  << ", sig_size=" << sig_size
                  << "\n";

        const size_t verify_iters = (algo == "rsa-pss-3072") ? 300 : 1000;
        const double verify_total = measure_ms_bench([&]() {
            for (size_t i = 0; i < verify_iters; ++i) {
                const bool ok = verify_file_detached(algo, pub_path.string(), msg_path.string(), sig_path.string());
                if (!ok) {
                    throw std::runtime_error("benchmark verify failed for " + algo);
                }
            }
        });

        out << algo << ",verify," << verify_iters << ","
            << verify_total << ","
            << (verify_total / static_cast<double>(verify_iters)) << ","
            << (1000.0 * static_cast<double>(verify_iters) / verify_total) << ","
            << sig_size << "\n";

        std::cout << "[OK] " << algo
                  << " verify avg_ms="
                  << (verify_total / static_cast<double>(verify_iters))
                  << "\n";
    }

    std::cout << "[OK] Signature benchmark completed\n";
}

} // namespace sigtool
