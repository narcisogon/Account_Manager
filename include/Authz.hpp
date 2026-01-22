#pragma once
#include <string>

class DB;

class Authz {
public:
    explicit Authz(DB& db);
    bool has_permission(const std::string& username, const std::string& perm_name) const;

private:
    DB& m_db;
};
