-- Add system user with reserved ID 1
INSERT INTO users (id, email, first_name, last_name, created_at, created_by, updated_at, updated_by)
VALUES (
    -1,
    'system@system.com',
    'system',
    'system',
    now(),
    -1,
    now(),
    -1
);