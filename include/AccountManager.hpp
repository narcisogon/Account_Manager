#pragma once
#include <string>

class DB;
class Authz;

class AccountManager {
public:
    AccountManager(DB& db, Authz& authz);

    void create_user(const std::string& actor, const std::string& username,
                     const std::string& email, const std::string& password_hash);

    void disable_user(const std::string& actor, const std::string& username);

    void assign_role(const std::string& actor, const std::string& username,
                     const std::string& role_name);

    bool verify_password(const std::string& username, const std::string& plain_password) const;
    std::string login(const std::string& username, const std::string& plain_password, int ttl_minutes);
    bool logout(const std::string& session_token);
    bool validate_session(const std::string& session_token) const;

    void list_user_roles(const std::string& username) const;

    void list_role_permissions(const std::string& role_name) const;

private:
    DB& m_db;
    Authz& m_authz;

    void require(const std::string& actor, const std::string& permission) const;
};
