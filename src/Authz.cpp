#include "Authz.hpp"
#include "Database.hpp"
#include <pqxx/pqxx>

Authz::Authz(DB& db) : m_db(db) {}

bool Authz::has_permission(const std::string& username, const std::string& perm_name) const {
    pqxx::read_transaction tx(m_db.conn());
    auto res = tx.exec_prepared("check_permission", username, perm_name);
    if (res.empty()) return false;
    return res[0]["has_permission"].as<bool>();
}
