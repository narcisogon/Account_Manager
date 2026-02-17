#pragma once
#include <string>

namespace password {

std::string hash_argon2id(const std::string& plain_password);
bool verify_argon2id(const std::string& plain_password, const std::string& encoded_hash);

} // namespace password
