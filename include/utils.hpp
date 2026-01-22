#pragma once
#include <iostream>
#include <string>
#include <cstdlib>

namespace utils {

inline void fail(const std::string& msg) {
    std::cerr << "[ERROR] " << msg << "\n";
    std::exit(1);
}

inline void info(const std::string& msg) {
    std::cout << "[INFO] " << msg << "\n";
}

inline void ok(const std::string& msg) {
    std::cout << "[OK] " << msg << "\n";
}

} // namespace utils
