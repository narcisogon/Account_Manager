#include "Database.hpp"
#include "Authz.hpp"
#include "Audit.hpp"
#include "AccountManager.hpp"
#include "ConfigManager.hpp"
#include "utils.hpp"
#include <string>
#include <iostream>

static void print_help() {
    std::cout << R"(
Usage:
  ./accountmgr "<conn_string>" <command> [args...]

User:
  create-user <actor> <username> <email> <password_hash>
  disable-user <actor> <username>
  assign-role <actor> <username> <role_name>
  list-user-roles <username>
  list-role-permissions <role_name>

Config:
  add-host <actor> <hostname> <host_type> <ip> <os_name> <notes>
  list-hosts
  create-profile <actor> <profile_name> <description>
  set-profile-setting <actor> <profile_name> <setting_key> <json_value>
  apply-profile <actor> <hostname> <profile_name>
  grant-host-access <actor> <username> <hostname> <access_level>
  list-host-access <username>

Audit:
  show-audit [limit]
)" << "\n";
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        print_help();
        return 0;
    }

    const std::string conn_str = argv[1];
    const std::string cmd = argv[2];

    try {
        DB db(conn_str);
        Authz authz(db);
        Audit audit(db);

        AccountManager accounts(db, authz);
        ConfigManager config(db, authz);

        // USER MANAGEMENT
        if (cmd == "create-user") {
            if (argc != 7) utils::fail("create-user <actor> <username> <email> <password_hash>");
            accounts.create_user(argv[3], argv[4], argv[5], argv[6]);
        }
        else if (cmd == "disable-user") {
            if (argc != 5) utils::fail("disable-user <actor> <username>");
            accounts.disable_user(argv[3], argv[4]);
        }
        else if (cmd == "assign-role") {
            if (argc != 6) utils::fail("assign-role <actor> <username> <role_name>");
            accounts.assign_role(argv[3], argv[4], argv[5]);
        }
        else if (cmd == "list-user-roles") {
            if (argc != 4) utils::fail("list-user-roles <username>");
            accounts.list_user_roles(argv[3]);
        }
        else if (cmd == "list-role-permissions") {
            if (argc != 4) utils::fail("list-role-permissions <role_name>");
            accounts.list_role_permissions(argv[3]);
        }

        // CONFIG / HOSTS
        else if (cmd == "add-host") {
            if (argc != 9) utils::fail("add-host <actor> <hostname> <host_type> <ip> <os_name> <notes>");
            config.add_host(argv[3], argv[4], argv[5], argv[6], argv[7], argv[8]);
        }
        else if (cmd == "list-hosts") {
            config.list_hosts();
        }
        else if (cmd == "create-profile") {
            if (argc != 6) utils::fail("create-profile <actor> <profile_name> <description>");
            config.create_profile(argv[3], argv[4], argv[5]);
        }
        else if (cmd == "set-profile-setting") {
            if (argc != 7) utils::fail("set-profile-setting <actor> <profile_name> <setting_key> <json_value>");
            config.set_profile_setting(argv[3], argv[4], argv[5], argv[6]);
        }
        else if (cmd == "apply-profile") {
            if (argc != 6) utils::fail("apply-profile <actor> <hostname> <profile_name>");
            config.apply_profile(argv[3], argv[4], argv[5]);
        }
        else if (cmd == "grant-host-access") {
            if (argc != 7) utils::fail("grant-host-access <actor> <username> <hostname> <access_level>");
            config.grant_host_access(argv[3], argv[4], argv[5], argv[6]);
        }
        else if (cmd == "list-host-access") {
            if (argc != 4) utils::fail("list-host-access <username>");
            config.list_host_access(argv[3]);
        }

        // AUDIT
        else if (cmd == "show-audit") {
            int limit = 25;
            if (argc == 4) limit = std::stoi(argv[3]);
            audit.show(limit);
        }
        else {
            print_help();
        }

    } catch (const pqxx::sql_error& e) {
        std::cerr << "[SQL ERROR] " << e.what() << "\nQuery: " << e.query() << "\n";
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "[EXCEPTION] " << e.what() << "\n";
        return 1;
    }

    return 0;
}
