#include "Audit.hpp"
#include "Database.hpp"
#include "utils.hpp"
#include <pqxx/pqxx>
#include <iostream>

Audit::Audit(DB& db) : m_db(db) {}

void Audit::write(const std::string& actor_username,
                  const std::string& action,
                  const std::string& target_table,
                  const std::string& target_id_uuid,
                  const std::string& details_json) {
    pqxx::work tx(m_db.conn());
    tx.exec_prepared("write_audit", actor_username, action, target_table, target_id_uuid, details_json);
    tx.commit();
}

void Audit::show(int limit) const {
    pqxx::read_transaction tx(m_db.conn());
    auto res = tx.exec_prepared("show_audit", limit);

    if (res.empty()) {
        utils::info("No audit events.");
        return;
    }

    std::cout << "Audit (latest " << limit << "):\n";
    for (auto row : res) {
        std::cout
            << "  [" << row["created_at"].c_str() << "] "
            << (row["actor"].is_null() ? "<null>" : row["actor"].c_str())
            << " | " << row["action"].c_str()
            << " | table=" << (row["target_table"].is_null() ? "<null>" : row["target_table"].c_str())
            << " | id=" << (row["target_id"].is_null() ? "<null>" : row["target_id"].c_str())
            << "\n";
    }
}
