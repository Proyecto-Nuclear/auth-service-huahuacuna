-- Script para activar manualmente un usuario después del registro
-- (Útil para testing cuando no hay servicio de email configurado)

-- 1. Activar un padrino específico por email
UPDATE users
SET "emailVerified" = true,
    status = 'ACTIVE',
    "emailVerificationToken" = null
WHERE email = 'juan@example.com';

-- 2. Ver usuarios pendientes de activación
SELECT
    id,
    email,
    name,
    role,
    status,
    "emailVerified",
    "createdAt"
FROM users
WHERE status = 'PENDING_ACTIVATION'
ORDER BY "createdAt" DESC;

-- 3. Obtener token de verificación de un usuario (para testing del endpoint)
SELECT
    email,
    "emailVerificationToken"
FROM users
WHERE email = 'juan@example.com';

-- 4. Obtener token de reset de contraseña (para testing del endpoint)
SELECT
    email,
    "resetPasswordToken",
    "resetPasswordExpires"
FROM users
WHERE email = 'juan@example.com';

-- 5. Ver todos los usuarios del sistema
SELECT
    id,
    email,
    name,
    role,
    status,
    "emailVerified",
    "lastLoginAt",
    "createdAt"
FROM users
ORDER BY id;

-- 6. Ver logs de auditoría recientes
SELECT
    al.id,
    al.action,
    al."createdAt",
    al."ipAddress",
    u1.email as affected_user,
    u2.email as performed_by,
    al.metadata
FROM audit_logs al
LEFT JOIN users u1 ON al."userId" = u1.id
LEFT JOIN users u2 ON al."performedBy" = u2.id
ORDER BY al."createdAt" DESC
LIMIT 20;

-- 7. Desbloquear una cuenta bloqueada por intentos fallidos
UPDATE users
SET "failedLoginCount" = 0,
    "lockedUntil" = null
WHERE email = 'juan@example.com';

-- 8. Ver refresh tokens activos de un usuario
SELECT
    rt.id,
    rt.token,
    rt."expiresAt",
    rt."revokedAt",
    rt."createdAt",
    u.email
FROM refresh_tokens rt
JOIN users u ON rt."userId" = u.id
WHERE u.email = 'juan@example.com'
ORDER BY rt."createdAt" DESC;
