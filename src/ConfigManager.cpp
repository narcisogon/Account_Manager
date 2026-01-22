#include "ConfigManager.hpp"
#include "Database.hpp"
#include "Authz.hpp"
#include "utils.hpp"
#include <pqxx/pqxx>
#include <iostream>

ConfigManager::ConfigManager(DB& db, Authz& authz) : m_db(db), m_authz(authz) {}

void ConfigManager::require(const std::string& actor, const std::string& permission) const {
    if (!m_authz.has_permission(actor, permission)) {
        utils::fail("Authorization failed: '" + actor + "' lacks permission '" + permission + "'");
    }
}

void ConfigManager::add_host(const std::string& actor,
                             const std::string& hostname, const std::string& host_type,
                             const std::string& ip, const std::string& os_name, const std::string& notes) {
    require(actor, "manage_hosts");

    pqxx::work tx(m_db.conn());
    auto res = tx.exec_prepared("add_host", hostname, host_type, ip, os_name, notes);

    if (res.empty()) utils::info("Host '" + hostname + "' already exists.");
    else utils::ok("Added host '" + hostname + "'");
    tx.commit();
}

void ConfigManager::list_hosts() const {
    pqxx::read_transaction tx(m_db.conn());
    auto res = tx.exec_prepared("list_hosts");

    std::cout << "Hosts:\n";
    if (res.empty()) {
        std::cout << "  (none)\n";
        return;
    }

    for (auto row : res) {
        std::cout << "  - " << row["hostname"].c_str()
                  << " [" << row["host_type"].c_str() << "] "
                  << "ip=" << (row["ip_address"].is_null() ? "null" : row["ip_address"].c_str())
                  << " os=" << (row["os_name"].is_null() ? "null" : row["os_name"].c_str())
                  << "\n";
    }
}

void ConfigManager::create_profile(const std::string& actor,
                                   const std::string& profile_name, const std::string& description) {
    require(actor, "apply_config_profiles");

    pqxx::work tx(m_db.conn());
    auto res = tx.exec_prepared("create_profile", profile_name, description);

    if (res.empty()) utils::info("Profile '" + profile_name + "' already exists.");
    else utils::ok("Created profile '" + profile_name + "'");
    tx.commit();
}

void ConfigManager::set_profile_setting(const std::string& actor,
                                        const std::string& profile_name,
                                        const std::string& setting_key,
                                        const std::string& json_value) {
    require(actor, "apply_config_profiles");

    pqxx::work tx(m_db.conn());
    tx.exec_prepared("set_profile_setting", profile_name, setting_key, json_value);
    utils::ok("Set setting '" + setting_key + "' for profile '" + profile_name + "'");
    tx.commit();
}

void ConfigManager::apply_profile(const std::string& actor,
                                  const std::string& hostname, const std::string& profile_name) {
    require(actor, "apply_config_profiles");

    pqxx::work tx(m_db.conn());
    tx.exec_prepared("apply_profile", hostname, profile_name);
    utils::ok("Applied profile '" + profile_name + "' to host '" + hostname + "'");
    tx.commit();
}

void ConfigManager::grant_host_access(const std::string& actor,
                                      const std::string& username,
                                      const std::string& hostname,
                                      const std::string& access_level) {
    require(actor, "manage_hosts");

    pqxx::work tx(m_db.conn());
    tx.exec_prepared("grant_host_access", username, hostname, access_level);
    utils::ok("Granted " + access_level + " access for '" + username + "' on '" + hostname + "'");
    tx.commit();
}

void ConfigManager::list_host_access(const std::string& username) const {
    pqxx::read_transaction tx(m_db.conn());
    auto res = tx.exec_prepared("list_host_access", username);

    std::cout << "Host access for '" << username << "':\n";
    if (res.empty()) {
        std::cout << "  (none)\n";
        return;
    }

    for (auto row : res) {
        std::cout << "  - " << row["hostname"].c_str()
                  << " => " << row["access_level"].c_str()
                  << " (" << row["granted_at"].c_str() << ")"
                  << "\n";
    }
}
