export const safeUser = u => ({ id: u.id, login: u.login, name: u.name, role: u.role, blocked: Boolean(u.blocked), mustChange: Boolean(u.must_change), createdAt: u.created_at, passwordChangedAt: u.password_changed_at, otpExpiresAt: u.otp_expires_at });

