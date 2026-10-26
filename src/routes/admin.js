import { ROLES } from '../config/roles.js';
import { safeUser } from '../utils/user.js';
import { hash, otp } from '../services/passwords.js';
import { fail } from '../utils/http.js';

export function registerAdminRoutes(app, { db, getSettings, addUser, requireAuth, currentPassword, admin }) {
  app.use('/api/admin', requireAuth, currentPassword, admin);
  app.get('/api/admin/users', (req, res) => res.json(db.prepare('SELECT * FROM users ORDER BY id').all().map(safeUser)));
  const validAccount = b => b && typeof b.login === 'string' && /^[a-zA-Z0-9_.-]{3,40}$/.test(b.login) && typeof b.name === 'string' && b.name.trim().length >= 2 && b.name.length <= 80 && ROLES.includes(b.role);
  app.post('/api/admin/users', async (req, res) => {
    if (!validAccount(req.body)) return fail(res, 400, 'Sprawdź dane: login 3–40 znaków (litery, cyfry, _ . -), nazwa 2–80 znaków i poprawna rola.');
    if (db.prepare('SELECT id FROM users WHERE login=?').get(req.body.login)) return fail(res, 409, 'Ten login jest już zajęty.');
    res.status(201).json(await addUser(req.body.login, req.body.name.trim(), req.body.role));
  });
  app.put('/api/admin/users/:id', (req, res) => {
    const u = db.prepare('SELECT * FROM users WHERE id=?').get(req.params.id);
    if (!u) return fail(res, 404, 'Nie znaleziono konta.');
    if (!validAccount(req.body) || typeof req.body.blocked !== 'boolean') return fail(res, 400, 'Nieprawidłowe dane konta.');
    if (u.login === 'ADMIN' && (req.body.login !== 'ADMIN' || req.body.role !== 'Administrator' || req.body.blocked)) return fail(res, 400, 'Stałe konto ADMIN musi pozostać aktywnym administratorem.');
    if (u.id === req.user.id && (req.body.role !== 'Administrator' || req.body.blocked)) return fail(res, 400, 'Nie możesz odebrać sobie dostępu do administracji.');
    if (db.prepare('SELECT id FROM users WHERE login=? AND id!=?').get(req.body.login, u.id)) return fail(res, 409, 'Ten login jest już zajęty.');
    db.prepare('UPDATE users SET login=?,name=?,role=?,blocked=? WHERE id=?').run(req.body.login, req.body.name.trim(), req.body.role, Number(req.body.blocked), u.id);
    if (u.id !== req.user.id) db.prepare('DELETE FROM sessions WHERE user_id=?').run(u.id);
    res.json({ message: 'Zapisano konto.' });
  });
  app.delete('/api/admin/users/:id', (req, res) => {
    const u = db.prepare('SELECT * FROM users WHERE id=?').get(req.params.id);
    if (!u) return fail(res, 404, 'Nie znaleziono konta.');
    if (u.login === 'ADMIN' || u.id === req.user.id) return fail(res, 400, 'Nie możesz usunąć tego konta.');
    db.prepare('DELETE FROM sessions WHERE user_id=?').run(u.id);
    db.prepare('DELETE FROM users WHERE id=?').run(u.id);
    res.json({ message: 'Usunięto konto.' });
  });
  app.post('/api/admin/users/:id/reset', async (req, res) => {
    const u = db.prepare('SELECT * FROM users WHERE id=?').get(req.params.id);
    if (!u) return fail(res, 404, 'Nie znaleziono konta.');
    if (u.id === req.user.id) return fail(res, 400, 'Własne hasło zmień w zakładce Moje konto.');
    const password = otp(), newHash = await hash(password), expiresAt = Date.now() + 12 * 3600000;
    db.exec('BEGIN');
    try {
      db.prepare('INSERT INTO password_history (user_id,hash) VALUES (?,?)').run(u.id, u.password_hash);
      db.prepare('UPDATE users SET password_hash=?,must_change=1,otp_expires_at=? WHERE id=?').run(newHash, expiresAt, u.id);
      db.prepare('DELETE FROM sessions WHERE user_id=?').run(u.id);
      db.exec('COMMIT');
    } catch(e) { db.exec('ROLLBACK'); throw e; }
    res.json({ login: u.login, password, expiresAt });
  });
  app.put('/api/admin/settings', (req, res) => {
    const b = req.body;
    if (!b || typeof b.policyEnabled !== 'boolean' || !Number.isInteger(b.minLength) || b.minLength < 14 || b.minLength > 128 || !Number.isInteger(b.passwordDays) || b.passwordDays < 0 || b.passwordDays > 3650 || !Number.isInteger(b.idleMinutes) || b.idleMinutes < 1 || b.idleMinutes > 1440 || !Array.isArray(b.bannedWords) || b.bannedWords.length > 200 || !b.bannedWords.every(w => typeof w === 'string' && w.trim().length > 0 && w.length <= 80)) return fail(res, 400, 'Sprawdź zakresy ustawień i słownik (maksymalnie 200 słów).');
    db.prepare('UPDATE settings SET policy_enabled=?,min_length=?,password_days=?,idle_minutes=?,banned_words=? WHERE id=1').run(Number(b.policyEnabled), b.minLength, b.passwordDays, b.idleMinutes, JSON.stringify([...new Set(b.bannedWords.map(w => w.trim()))]));
    res.json(getSettings());
  });
}
