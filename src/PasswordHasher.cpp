#include "PasswordHasher.hpp"
#include <argon2.h>
#include <array>
#include <cstdint>
#include <fstream>
#include <random>
#include <stdexcept>
#include <vector>

namespace {

void fill_random_bytes(std::uint8_t* buffer, std::size_t size) {
    std::ifstream urandom("/dev/urandom", std::ios::in | std::ios::binary);
    if (urandom.good()) {
        urandom.read(reinterpret_cast<char*>(buffer), static_cast<std::streamsize>(size));
        if (urandom.good() || urandom.eof()) {
            if (urandom.gcount() == static_cast<std::streamsize>(size)) {
                return;
            }
        }
    }

    std::random_device rd;
    for (std::size_t i = 0; i < size; ++i) {
        buffer[i] = static_cast<std::uint8_t>(rd() & 0xFF);
    }
}

} // namespace

namespace password {

std::string hash_argon2id(const std::string& plain_password) {
    if (plain_password.empty()) {
        throw std::runtime_error("Password cannot be empty.");
    }

    constexpr std::uint32_t t_cost = 3;           // Iterations.
    constexpr std::uint32_t m_cost_kib = 1 << 16; // 64 MiB.
    constexpr std::uint32_t parallelism = 1;
    constexpr std::uint32_t salt_len = 16;
    constexpr std::uint32_t hash_len = 32;

    std::array<std::uint8_t, salt_len> salt{};
    fill_random_bytes(salt.data(), salt.size());

    const std::size_t encoded_len = argon2_encodedlen(
        t_cost,
        m_cost_kib,
        parallelism,
        salt_len,
        hash_len,
        Argon2_id
    );

    std::vector<char> encoded(encoded_len + 1, '\0');

    const int rc = argon2id_hash_encoded(
        t_cost,
        m_cost_kib,
        parallelism,
        plain_password.data(),
        plain_password.size(),
        salt.data(),
        salt.size(),
        hash_len,
        encoded.data(),
        encoded.size()
    );

    if (rc != ARGON2_OK) {
        throw std::runtime_error(std::string("Argon2 hashing failed: ") + argon2_error_message(rc));
    }

    return std::string(encoded.data());
}

bool verify_argon2id(const std::string& plain_password, const std::string& encoded_hash) {
    if (plain_password.empty() || encoded_hash.empty()) {
        return false;
    }

    const int rc = argon2id_verify(
        encoded_hash.c_str(),
        plain_password.data(),
        plain_password.size()
    );

    return rc == ARGON2_OK;
}

} // namespace password
