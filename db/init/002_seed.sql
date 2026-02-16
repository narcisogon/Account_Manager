INSERT INTO auth.permissions (perm_name, description)
VALUES
    ('manage_users', 'Create and disable user accounts'),
    ('manage_roles', 'Assign roles and manage RBAC mappings'),
    ('manage_hosts', 'Register hosts and manage host access'),
    ('apply_config_profiles', 'Create and apply config profiles')
ON CONFLICT (perm_name) DO NOTHING;

INSERT INTO auth.roles (role_name, description)
VALUES
    ('admin', 'Full administrative access'),
    ('operator', 'Operational host and profile management'),
    ('viewer', 'Read-only access')
ON CONFLICT (role_name) DO NOTHING;

INSERT INTO auth.role_permissions (role_id, perm_id)
SELECT r.role_id, p.perm_id
FROM auth.roles r
JOIN auth.permissions p ON p.perm_name IN (
    'manage_users',
    'manage_roles',
    'manage_hosts',
    'apply_config_profiles'
)
WHERE r.role_name = 'admin'
ON CONFLICT DO NOTHING;

INSERT INTO auth.role_permissions (role_id, perm_id)
SELECT r.role_id, p.perm_id
FROM auth.roles r
JOIN auth.permissions p ON p.perm_name IN (
    'manage_hosts',
    'apply_config_profiles'
)
WHERE r.role_name = 'operator'
ON CONFLICT DO NOTHING;

INSERT INTO auth.users (username, email, password_hash, is_active)
VALUES ('bootstrap_admin', 'bootstrap_admin@local', 'CHANGE_ME_PASSWORD_HASH', TRUE)
ON CONFLICT (username) DO NOTHING;

INSERT INTO auth.user_roles (user_id, role_id)
SELECT u.user_id, r.role_id
FROM auth.users u
JOIN auth.roles r ON r.role_name = 'admin'
WHERE u.username = 'bootstrap_admin'
ON CONFLICT DO NOTHING;
