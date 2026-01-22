#pragma once
#include <string>

class DB;
class Authz;

class ConfigManager {
public:
    ConfigManager(DB& db, Authz& authz);

    void add_host(const std::string& actor,
                  const std::string& hostname, const std::string& host_type,
                  const std::string& ip, const std::string& os_name, const std::string& notes);

    void list_hosts() const;

    void create_profile(const std::string& actor,
                        const std::string& profile_name, const std::string& description);

    void set_profile_setting(const std::string& actor,
                             const std::string& profile_name,
                             const std::string& setting_key,
                             const std::string& json_value);

    void apply_profile(const std::string& actor,
                       const std::string& hostname, const std::string& profile_name);

    void grant_host_access(const std::string& actor,
                           const std::string& username,
                           const std::string& hostname,
                           const std::string& access_level);

    void list_host_access(const std::string& username) const;

private:
    DB& m_db;
    Authz& m_authz;

    void require(const std::string& actor, const std::string& permission) const;
};
