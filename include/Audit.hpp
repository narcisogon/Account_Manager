#pragma once
#include <string>

class DB;

class Audit {
public:
    explicit Audit(DB& db);

    void write(const std::string& actor_username,
               const std::string& action,
               const std::string& target_table,
               const std::string& target_id_uuid,
               const std::string& details_json);

    void show(int limit) const;

private:
    DB& m_db;
};
