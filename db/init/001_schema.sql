CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE SCHEMA IF NOT EXISTS auth;
CREATE SCHEMA IF NOT EXISTS cfg;

CREATE TABLE IF NOT EXISTS auth.users (
    user_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS auth.roles (
    role_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    role_name TEXT NOT NULL UNIQUE,
    description TEXT
);

CREATE TABLE IF NOT EXISTS auth.permissions (
    perm_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    perm_name TEXT NOT NULL UNIQUE,
    description TEXT
);

CREATE TABLE IF NOT EXISTS auth.role_permissions (
    role_id UUID NOT NULL REFERENCES auth.roles(role_id) ON DELETE CASCADE,
    perm_id UUID NOT NULL REFERENCES auth.permissions(perm_id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, perm_id)
);

CREATE TABLE IF NOT EXISTS auth.user_roles (
    user_id UUID NOT NULL REFERENCES auth.users(user_id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES auth.roles(role_id) ON DELETE CASCADE,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, role_id)
);

CREATE TABLE IF NOT EXISTS cfg.hosts (
    host_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hostname TEXT NOT NULL UNIQUE,
    host_type TEXT NOT NULL,
    ip_address INET,
    os_name TEXT,
    notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS cfg.config_profiles (
    profile_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    profile_name TEXT NOT NULL UNIQUE,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS cfg.profile_settings (
    profile_id UUID NOT NULL REFERENCES cfg.config_profiles(profile_id) ON DELETE CASCADE,
    setting_key TEXT NOT NULL,
    setting_value JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (profile_id, setting_key)
);

CREATE TABLE IF NOT EXISTS cfg.host_profile_assignment (
    host_id UUID NOT NULL REFERENCES cfg.hosts(host_id) ON DELETE CASCADE,
    profile_id UUID NOT NULL REFERENCES cfg.config_profiles(profile_id) ON DELETE CASCADE,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (host_id, profile_id)
);

CREATE TABLE IF NOT EXISTS auth.user_host_access (
    user_id UUID NOT NULL REFERENCES auth.users(user_id) ON DELETE CASCADE,
    host_id UUID NOT NULL REFERENCES cfg.hosts(host_id) ON DELETE CASCADE,
    access_level TEXT NOT NULL,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, host_id)
);

CREATE TABLE IF NOT EXISTS auth.audit_log (
    audit_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_user_id UUID REFERENCES auth.users(user_id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    target_table TEXT,
    target_id UUID,
    details JSONB NOT NULL DEFAULT '{}'::JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
