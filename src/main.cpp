#include "Database.hpp"
#include "Authz.hpp"
#include "Audit.hpp"
#include "AccountManager.hpp"
#include "ConfigManager.hpp"
#include "utils.hpp"
#include <string>
#include <iostream>
#include <cstdlib>
#include <sstream>
#include <unordered_set>
#include <initializer_list>
#include <utility>

static bool is_known_command(const std::string& cmd) {
    static const std::unordered_set<std::string> commands = {
        "create-user",
        "disable-user",
        "assign-role",
        "list-user-roles",
        "list-role-permissions",
        "add-host",
        "list-hosts",
        "create-profile",
        "set-profile-setting",
        "apply-profile",
        "grant-host-access",
        "list-host-access",
        "show-audit"
    };
    return commands.find(cmd) != commands.end();
}

static std::string env_value(const char* key) {
    const char* val = std::getenv(key);
    return val == nullptr ? "" : std::string(val);
}

static std::string build_conn_string_from_env() {
    const std::string host = env_value("PGHOST");
    const std::string port = env_value("PGPORT");
    const std::string dbname = env_value("PGDATABASE");
    const std::string user = env_value("PGUSER");
    const std::string password = env_value("PGPASSWORD");

    if (dbname.empty() || user.empty()) {
        return "";
    }

    std::ostringstream conn;
    if (!host.empty()) conn << "host=" << host << " ";
    if (!port.empty()) conn << "port=" << port << " ";
    conn << "dbname=" << dbname << " user=" << user;
    if (!password.empty()) conn << " password=" << password;

    return conn.str();
}

static std::string json_escape(const std::string& value) {
    std::string out;
    out.reserve(value.size());

    for (char c : value) {
        switch (c) {
            case '\\': out += "\\\\"; break;
            case '"':  out += "\\\""; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default: out.push_back(c); break;
        }
    }

    return out;
}

static std::string make_details_json(std::initializer_list<std::pair<std::string, std::string>> fields) {
    std::string json = "{";
    bool first = true;

    for (const auto& field : fields) {
        if (!first) json += ",";
        first = false;
        json += "\"";
        json += json_escape(field.first);
        json += "\":\"";
        json += json_escape(field.second);
        json += "\"";
    }

    json += "}";
    return json;
}

static void print_help() {
    std::cout << R"(
Usage:
  ./accountmgr "<conn_string>" <command> [args...]
  ./accountmgr <command> [args...]   (uses PGHOST/PGPORT/PGDATABASE/PGUSER/PGPASSWORD)

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
    if (argc < 2) {
        print_help();
        return 0;
    }

    std::string conn_str;
    std::string cmd;
    int arg_base = 0;

    if (is_known_command(argv[1])) {
        cmd = argv[1];
        arg_base = 2;
        conn_str = build_conn_string_from_env();
        if (conn_str.empty()) {
            utils::fail(
                "No connection string provided. Pass \"<conn_string>\" or set PGDATABASE and PGUSER "
                "(plus PGHOST/PGPORT/PGPASSWORD as needed)."
            );
        }
    } else {
        if (argc < 3) {
            print_help();
            return 0;
        }
        conn_str = argv[1];
        cmd = argv[2];
        arg_base = 3;
    }

    try {
        DB db(conn_str);
        Authz authz(db);
        Audit audit(db);

        AccountManager accounts(db, authz);
        ConfigManager config(db, authz);

        auto require_args = [&](int expected_count, const std::string& usage) {
            if (argc != arg_base + expected_count) utils::fail(usage);
        };

        auto arg = [&](int index) -> const char* {
            return argv[arg_base + index];
        };

        // USER MANAGEMENT
        if (cmd == "create-user") {
            require_args(4, "create-user <actor> <username> <email> <password_hash>");
            const std::string actor = arg(0);
            const std::string username = arg(1);
            const std::string email = arg(2);
            const std::string password_hash = arg(3);

            accounts.create_user(actor, username, email, password_hash);
            audit.write(
                actor,
                "create_user",
                "auth.users",
                "",
                make_details_json({{"username", username}, {"email", email}})
            );
        }
        else if (cmd == "disable-user") {
            require_args(2, "disable-user <actor> <username>");
            const std::string actor = arg(0);
            const std::string username = arg(1);

            accounts.disable_user(actor, username);
            audit.write(
                actor,
                "disable_user",
                "auth.users",
                "",
                make_details_json({{"username", username}})
            );
        }
        else if (cmd == "assign-role") {
            require_args(3, "assign-role <actor> <username> <role_name>");
            const std::string actor = arg(0);
            const std::string username = arg(1);
            const std::string role_name = arg(2);

            accounts.assign_role(actor, username, role_name);
            audit.write(
                actor,
                "assign_role",
                "auth.user_roles",
                "",
                make_details_json({{"username", username}, {"role_name", role_name}})
            );
        }
        else if (cmd == "list-user-roles") {
            require_args(1, "list-user-roles <username>");
            accounts.list_user_roles(arg(0));
        }
        else if (cmd == "list-role-permissions") {
            require_args(1, "list-role-permissions <role_name>");
            accounts.list_role_permissions(arg(0));
        }

        // CONFIG / HOSTS
        else if (cmd == "add-host") {
            require_args(6, "add-host <actor> <hostname> <host_type> <ip> <os_name> <notes>");
            const std::string actor = arg(0);
            const std::string hostname = arg(1);
            const std::string host_type = arg(2);
            const std::string ip = arg(3);
            const std::string os_name = arg(4);
            const std::string notes = arg(5);

            config.add_host(actor, hostname, host_type, ip, os_name, notes);
            audit.write(
                actor,
                "add_host",
                "cfg.hosts",
                "",
                make_details_json({{"hostname", hostname}, {"host_type", host_type}, {"ip", ip}})
            );
        }
        else if (cmd == "list-hosts") {
            require_args(0, "list-hosts");
            config.list_hosts();
        }
        else if (cmd == "create-profile") {
            require_args(3, "create-profile <actor> <profile_name> <description>");
            const std::string actor = arg(0);
            const std::string profile_name = arg(1);
            const std::string description = arg(2);

            config.create_profile(actor, profile_name, description);
            audit.write(
                actor,
                "create_profile",
                "cfg.config_profiles",
                "",
                make_details_json({{"profile_name", profile_name}})
            );
        }
        else if (cmd == "set-profile-setting") {
            require_args(4, "set-profile-setting <actor> <profile_name> <setting_key> <json_value>");
            const std::string actor = arg(0);
            const std::string profile_name = arg(1);
            const std::string setting_key = arg(2);
            const std::string json_value = arg(3);

            config.set_profile_setting(actor, profile_name, setting_key, json_value);
            audit.write(
                actor,
                "set_profile_setting",
                "cfg.profile_settings",
                "",
                make_details_json({{"profile_name", profile_name}, {"setting_key", setting_key}})
            );
        }
        else if (cmd == "apply-profile") {
            require_args(3, "apply-profile <actor> <hostname> <profile_name>");
            const std::string actor = arg(0);
            const std::string hostname = arg(1);
            const std::string profile_name = arg(2);

            config.apply_profile(actor, hostname, profile_name);
            audit.write(
                actor,
                "apply_profile",
                "cfg.host_profile_assignment",
                "",
                make_details_json({{"hostname", hostname}, {"profile_name", profile_name}})
            );
        }
        else if (cmd == "grant-host-access") {
            require_args(4, "grant-host-access <actor> <username> <hostname> <access_level>");
            const std::string actor = arg(0);
            const std::string username = arg(1);
            const std::string hostname = arg(2);
            const std::string access_level = arg(3);

            config.grant_host_access(actor, username, hostname, access_level);
            audit.write(
                actor,
                "grant_host_access",
                "auth.user_host_access",
                "",
                make_details_json({{"username", username}, {"hostname", hostname}, {"access_level", access_level}})
            );
        }
        else if (cmd == "list-host-access") {
            require_args(1, "list-host-access <username>");
            config.list_host_access(arg(0));
        }

        // AUDIT
        else if (cmd == "show-audit") {
            int limit = 25;
            if (argc == arg_base + 1) {
                limit = std::stoi(arg(0));
            } else if (argc != arg_base) {
                utils::fail("show-audit [limit]");
            }
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
