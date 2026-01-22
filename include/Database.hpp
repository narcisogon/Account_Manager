#pragma once
#include <pqxx/pqxx>
#include <string>

class DB {
public:
    explicit DB(const std::string& conn_str);
    pqxx::connection& conn();

private:
    pqxx::connection m_conn;
    void prepare_statements();
};
