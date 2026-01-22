#include "AccountManager.hpp"
#include "Database.hpp"
#include "authz.hpp"
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
    utils::ok("Disabled '" + username + "' (rows=" + std::to_string(r.affected_rows()) + ")");
    tx.commit();
}

void AccountManager::assign_role(const std::string& actor, const std::string& username,
                                 const std::string& role_name) {
    require(actor, "manage_roles");

    pqxx::work tx(m_db.conn());
    tx.exec_prepared("assign_role", username, role_name);
    utils::ok("Assigned role '" + role_name + "' to '" + username + "'");
    tx.commit();
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
