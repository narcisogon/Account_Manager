#include "Database.hpp"
#include "utils.hpp"

DB::DB(const std::string& conn_str) : m_conn(conn_str) {
    if (!m_conn.is_open()) {
        utils::fail("Could not open PostgreSQL connection.");
    }
    prepare_statements();
}

pqxx::connection& DB::conn() {
    return m_conn;
}

void DB::prepare_statements() {
    // USERS
    m_conn.prepare("create_user",
        "INSERT INTO auth.users (username, email, password_hash) "
        "VALUES ($1, $2, $3) "
        "ON CONFLICT (username) DO NOTHING "
        "RETURNING user_id;");

    m_conn.prepare("disable_user",
        "UPDATE auth.users SET is_active = FALSE "
        "WHERE username = $1 AND is_active = TRUE;");

    m_conn.prepare("assign_role",
        "INSERT INTO auth.user_roles (user_id, role_id) "
        "SELECT u.user_id, r.role_id "
        "FROM auth.users u JOIN auth.roles r ON r.role_name = $2 "
        "WHERE u.username = $1 AND u.is_active = TRUE "
        "ON CONFLICT DO NOTHING;");

    m_conn.prepare("get_user_auth_record",
        "SELECT password_hash, is_active "
        "FROM auth.users "
        "WHERE username = $1;");

    m_conn.prepare("create_session",
        "INSERT INTO auth.sessions (user_id, session_token, expires_at) "
        "SELECT u.user_id, gen_random_uuid()::text, NOW() + ($2::int * INTERVAL '1 minute') "
        "FROM auth.users u "
        "WHERE u.username = $1 AND u.is_active = TRUE "
        "RETURNING session_token, expires_at;");

    m_conn.prepare("revoke_session",
        "UPDATE auth.sessions "
        "SET revoked_at = NOW() "
        "WHERE session_token = $1 "
        "  AND revoked_at IS NULL "
        "  AND expires_at > NOW();");

    m_conn.prepare("check_session",
        "SELECT u.username, u.is_active, "
        "       (s.expires_at <= NOW()) AS is_expired, "
        "       (s.revoked_at IS NOT NULL) AS is_revoked "
        "FROM auth.sessions s "
        "JOIN auth.users u ON u.user_id = s.user_id "
        "WHERE s.session_token = $1;");

    m_conn.prepare("list_user_roles",
        "SELECT r.role_name "
        "FROM auth.users u "
        "JOIN auth.user_roles ur ON ur.user_id = u.user_id "
        "JOIN auth.roles r ON r.role_id = ur.role_id "
        "WHERE u.username = $1 "
        "ORDER BY r.role_name;");

    // RBAC
    m_conn.prepare("check_permission",
        "SELECT EXISTS ("
        "  SELECT 1 "
        "  FROM auth.users u "
        "  JOIN auth.user_roles ur ON ur.user_id = u.user_id "
        "  JOIN auth.roles r ON r.role_id = ur.role_id "
        "  JOIN auth.role_permissions rp ON rp.role_id = r.role_id "
        "  JOIN auth.permissions p ON p.perm_id = rp.perm_id "
        "  WHERE u.username = $1 "
        "    AND u.is_active = TRUE "
        "    AND p.perm_name = $2"
        ") AS has_permission;");

    m_conn.prepare("list_role_permissions",
        "SELECT p.perm_name "
        "FROM auth.roles r "
        "JOIN auth.role_permissions rp ON rp.role_id = r.role_id "
        "JOIN auth.permissions p ON p.perm_id = rp.perm_id "
        "WHERE r.role_name = $1 "
        "ORDER BY p.perm_name;");

    // HOSTS
    m_conn.prepare("add_host",
        "INSERT INTO cfg.hosts (hostname, host_type, ip_address, os_name, notes) "
        "VALUES ($1, $2, $3::inet, $4, $5) "
        "ON CONFLICT (hostname) DO NOTHING "
        "RETURNING host_id;");

    m_conn.prepare("list_hosts",
        "SELECT hostname, host_type, ip_address, os_name, notes, created_at "
        "FROM cfg.hosts ORDER BY hostname;");

    // PROFILES
    m_conn.prepare("create_profile",
        "INSERT INTO cfg.config_profiles (profile_name, description) "
        "VALUES ($1, $2) "
        "ON CONFLICT (profile_name) DO NOTHING "
        "RETURNING profile_id;");

    m_conn.prepare("set_profile_setting",
        "INSERT INTO cfg.profile_settings (profile_id, setting_key, setting_value) "
        "SELECT p.profile_id, $2, $3::jsonb "
        "FROM cfg.config_profiles p "
        "WHERE p.profile_name = $1 "
        "ON CONFLICT (profile_id, setting_key) DO UPDATE "
        "SET setting_value = EXCLUDED.setting_value;");

    m_conn.prepare("apply_profile",
        "INSERT INTO cfg.host_profile_assignment (host_id, profile_id) "
        "SELECT h.host_id, p.profile_id "
        "FROM cfg.hosts h JOIN cfg.config_profiles p "
        "ON h.hostname = $1 AND p.profile_name = $2 "
        "ON CONFLICT DO NOTHING;");

    // HOST ACCESS
    m_conn.prepare("grant_host_access",
        "INSERT INTO auth.user_host_access (user_id, host_id, access_level) "
        "SELECT u.user_id, h.host_id, $3 "
        "FROM auth.users u JOIN cfg.hosts h "
        "ON u.username = $1 AND h.hostname = $2 "
        "WHERE u.is_active = TRUE "
        "ON CONFLICT (user_id, host_id) DO UPDATE "
        "SET access_level = EXCLUDED.access_level;");

    m_conn.prepare("list_host_access",
        "SELECT h.hostname, a.access_level, a.granted_at "
        "FROM auth.user_host_access a "
        "JOIN auth.users u ON u.user_id = a.user_id "
        "JOIN cfg.hosts h ON h.host_id = a.host_id "
        "WHERE u.username = $1 "
        "ORDER BY h.hostname;");

    // AUDIT
    m_conn.prepare("write_audit",
        "INSERT INTO auth.audit_log (actor_user_id, action, target_table, target_id, details) "
        "VALUES ("
        "  (SELECT u.user_id FROM auth.users u WHERE u.username = $1), "
        "  $2, "
        "  $3, "
        "  NULLIF($4, '')::uuid, "
        "  $5::jsonb"
        ");");

    m_conn.prepare("show_audit",
        "SELECT a.created_at, u.username AS actor, a.action, a.target_table, a.target_id, a.details "
        "FROM auth.audit_log a "
        "LEFT JOIN auth.users u ON u.user_id = a.actor_user_id "
        "ORDER BY a.created_at DESC "
        "LIMIT $1;");
}
