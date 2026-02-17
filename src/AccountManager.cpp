#include "AccountManager.hpp"
#include "Database.hpp"
#include "Authz.hpp"
#include "PasswordHasher.hpp"
#include "utils.hpp"
#include <pqxx/pqxx>
#include <iostream>

AccountManager::AccountManager(DB& db, Authz& authz) : m_db(db), m_authz(authz) {}

void AccountManager::require(const std::string& actor, const std::string& permission) const {
    if (!m_authz.has_permission(actor, permission)) {
        utils::fail("Authorization failed: '" + actor + "' lacks permission '" + permission + "'");
    }
}

void AccountManager::create_user(const std::string& actor, const std::string& username,
                                 const std::string& email, const std::string& password_hash) {
    require(actor, "manage_users");

    pqxx::work tx(m_db.conn());
    auto res = tx.exec_prepared("create_user", username, email, password_hash);

    if (res.empty()) {
        utils::info("User '" + username + "' already exists.");
    } else {
        utils::ok("Created user '" + username + "'");
    }

    tx.commit();
}

void AccountManager::disable_user(const std::string& actor, const std::string& username) {
    require(actor, "manage_users");

    pqxx::work tx(m_db.conn());
    auto r = tx.exec_prepared("disable_user", username);
    if (r.affected_rows() == 0) {
        utils::info("No active user '" + username + "' found.");
    } else {
        utils::ok("Disabled '" + username + "'");
    }
    tx.commit();
}

void AccountManager::assign_role(const std::string& actor, const std::string& username,
                                 const std::string& role_name) {
    require(actor, "manage_roles");

    pqxx::work tx(m_db.conn());
    auto r = tx.exec_prepared("assign_role", username, role_name);
    if (r.affected_rows() == 0) {
        utils::info("No role assignment changed for '" + username + "' and role '" + role_name + "'");
    } else {
        utils::ok("Assigned role '" + role_name + "' to '" + username + "'");
    }
    tx.commit();
}

bool AccountManager::verify_password(const std::string& username, const std::string& plain_password) const {
    pqxx::read_transaction tx(m_db.conn());
    auto res = tx.exec_prepared("get_user_auth_record", username);

    if (res.empty()) {
        utils::info("Invalid credentials.");
        return false;
    }

    const bool is_active = res[0]["is_active"].as<bool>();
    if (!is_active) {
        utils::info("Invalid credentials.");
        return false;
    }

    const std::string stored_hash = res[0]["password_hash"].as<std::string>();
    const bool verified = password::verify_argon2id(plain_password, stored_hash);

    if (verified) {
        utils::ok("Password verified for '" + username + "'");
    } else {
        utils::info("Invalid credentials.");
    }

    return verified;
}

std::string AccountManager::login(const std::string& username, const std::string& plain_password, int ttl_minutes) {
    if (ttl_minutes <= 0) {
        utils::fail("ttl_minutes must be greater than zero.");
    }

    if (!verify_password(username, plain_password)) {
        return "";
    }

    pqxx::work tx(m_db.conn());
    auto res = tx.exec_prepared("create_session", username, ttl_minutes);
    if (res.empty()) {
        utils::info("Login failed.");
        return "";
    }

    const std::string session_token = res[0]["session_token"].as<std::string>();
    const std::string expires_at = res[0]["expires_at"].as<std::string>();

    tx.commit();

    utils::ok("Login successful for '" + username + "'");
    std::cout << "Session token: " << session_token << "\n";
    std::cout << "Expires at: " << expires_at << "\n";
    return session_token;
}

bool AccountManager::logout(const std::string& session_token) {
    pqxx::work tx(m_db.conn());
    auto r = tx.exec_prepared("revoke_session", session_token);
    tx.commit();

    if (r.affected_rows() == 0) {
        utils::info("No active session found for the provided token.");
        return false;
    }

    utils::ok("Session revoked.");
    return true;
}

bool AccountManager::validate_session(const std::string& session_token) const {
    pqxx::read_transaction tx(m_db.conn());
    auto res = tx.exec_prepared("check_session", session_token);

    if (res.empty()) {
        utils::info("Session is invalid.");
        return false;
    }

    const std::string username = res[0]["username"].as<std::string>();
    const bool user_active = res[0]["is_active"].as<bool>();
    const bool is_expired = res[0]["is_expired"].as<bool>();
    const bool is_revoked = res[0]["is_revoked"].as<bool>();

    if (!user_active) {
        utils::info("Session is invalid: user is inactive.");
        return false;
    }

    if (is_revoked) {
        utils::info("Session is revoked.");
        return false;
    }

    if (is_expired) {
        utils::info("Session is expired.");
        return false;
    }

    utils::ok("Session is valid for '" + username + "'");
    return true;
}

void AccountManager::list_user_roles(const std::string& username) const {
    pqxx::read_transaction tx(m_db.conn());
    auto res = tx.exec_prepared("list_user_roles", username);

    std::cout << "Roles for '" << username << "':\n";
    if (res.empty()) {
        std::cout << "  (none)\n";
        return;
    }

    for (auto row : res) {
        std::cout << "  - " << row["role_name"].c_str() << "\n";
    }
}

void AccountManager::list_role_permissions(const std::string& role_name) const {
    pqxx::read_transaction tx(m_db.conn());
    auto res = tx.exec_prepared("list_role_permissions", role_name);

    std::cout << "Permissions for role '" << role_name << "':\n";
    if (res.empty()) {
        std::cout << "  (none)\n";
        return;
    }

    for (auto row : res) {
        std::cout << "  - " << row["perm_name"].c_str() << "\n";
    }
}
