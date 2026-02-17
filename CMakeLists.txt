cmake_minimum_required(VERSION 3.16)
project(account_manager_cli LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# On Ubuntu/Debian install: sudo apt install libpqxx-dev libpq-dev
find_package(PkgConfig REQUIRED)
pkg_check_modules(PQXX REQUIRED libpqxx)

add_executable(accountmgr
    src/main.cpp
    src/Database.cpp
    src/Authz.cpp
    src/Audit.cpp
    src/AccountManager.cpp
    src/ConfigManager.cpp
    src/PasswordHasher.cpp
)

target_include_directories(accountmgr PRIVATE include ${PQXX_INCLUDE_DIRS})
target_link_libraries(accountmgr PRIVATE ${PQXX_LIBRARIES} argon2)
target_compile_options(accountmgr PRIVATE ${PQXX_CFLAGS_OTHER})
