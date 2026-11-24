import { ROLES } from '../config/roles.js';
import { safeUser } from '../utils/user.js';
import { hash, otp } from '../services/passwords.js';
import { fail } from '../utils/http.js';

export function registerAdminRoutes(app, { db, getSettings, addUser, requireAuth, currentPassword, admin, audit }) {
  app.use('/api/admin', requireAuth, currentPassword, admin);
  app.get('/api/admin/users', (req, res) => res.json(db.prepare('SELECT * FROM users ORDER BY id').all().map(safeUser)));
  const validAccount = b => b && typeof b.login === 'string' && /^[a-zA-Z0-9_.-]{3,40}$/.test(b.login) && typeof b.name === 'string' && b.name.trim().length >= 2 && b.name.length <= 80 && ROLES.includes(b.role);

  app.post('/api/admin/users', async (req, res) => {
    if (!validAccount(req.body)) return fail(res, 400, 'Sprawdź dane: login 3–40 znaków (litery, cyfry, _ . -), nazwa 2–80 znaków i poprawna rola.');
    if (db.prepare('SELECT id FROM users WHERE login=?').get(req.body.login)) return fail(res, 409, 'Ten login jest już zajęty.');
    const created = await addUser(req.body.login, req.body.name.trim(), req.body.role);
    audit.log({ user: req.user.login, ip: req.ip, action: 'USER_CREATE', description: `Utworzono konto ${created.login} (rola: ${req.body.role}).`, result: 'sukces' });
    res.status(201).json(created);
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
    if (req.body.blocked && !u.blocked) {
      audit.log({ user: req.user.login, ip: req.ip, action: 'USER_BLOCK', description: `Zablokowano konto ${u.login}.`, result: 'sukces' });
    } else if (!req.body.blocked && u.blocked) {
      audit.log({ user: req.user.login, ip: req.ip, action: 'USER_UNBLOCK', description: `Odblokowano konto ${u.login}.`, result: 'sukces' });
    }
    if (req.body.role !== u.role) {
      audit.log({ user: req.user.login, ip: req.ip, action: 'ROLE_CHANGE', description: `Zmieniono rolę ${u.login}: ${u.role} -> ${req.body.role}.`, result: 'sukces' });
    } else if (req.body.blocked === Boolean(u.blocked)) {
      audit.log({ user: req.user.login, ip: req.ip, action: 'USER_UPDATE', description: `Zaktualizowano dane konta ${req.body.login}.`, result: 'sukces' });
    }
    res.json({ message: 'Zapisano konto.' });
  });

  app.delete('/api/admin/users/:id', (req, res) => {
    const u = db.prepare('SELECT * FROM users WHERE id=?').get(req.params.id);
    if (!u) return fail(res, 404, 'Nie znaleziono konta.');
    if (u.login === 'ADMIN' || u.id === req.user.id) return fail(res, 400, 'Nie możesz usunąć tego konta.');
    db.prepare('DELETE FROM sessions WHERE user_id=?').run(u.id);
    db.prepare('DELETE FROM users WHERE id=?').run(u.id);
    audit.log({ user: req.user.login, ip: req.ip, action: 'USER_DELETE', description: `Usunięto konto ${u.login}.`, result: 'sukces' });
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
    audit.log({ user: req.user.login, ip: req.ip, action: 'PASSWORD_RESET', description: `Zresetowano hasło dla ${u.login}.`, result: 'sukces' });
    res.json({ login: u.login, password, expiresAt });
  });

  app.put('/api/admin/settings', (req, res) => {
    const b = req.body;
    if (!b || typeof b.policyEnabled !== 'boolean' || !Number.isInteger(b.minLength) || b.minLength < 14 || b.minLength > 128 || !Number.isInteger(b.passwordDays) || b.passwordDays < 0 || b.passwordDays > 3650 || !Number.isInteger(b.idleMinutes) || b.idleMinutes < 1 || b.idleMinutes > 1440 || !Array.isArray(b.bannedWords) || b.bannedWords.length > 200 || !b.bannedWords.every(w => typeof w === 'string' && w.trim().length > 0 && w.length <= 80)) return fail(res, 400, 'Sprawdź zakresy ustawień i słownik (maksymalnie 200 słów).');
    db.prepare('UPDATE settings SET policy_enabled=?,min_length=?,password_days=?,idle_minutes=?,banned_words=? WHERE id=1').run(Number(b.policyEnabled), b.minLength, b.passwordDays, b.idleMinutes, JSON.stringify([...new Set(b.bannedWords.map(w => w.trim()))]));
    audit.log({ user: req.user.login, ip: req.ip, action: 'SETTINGS_UPDATE', description: `Zmieniono politykę haseł (minLength=${b.minLength}, idle=${b.idleMinutes}).`, result: 'sukces' });
    res.json(getSettings());
  });

  app.get('/api/admin/logs', (req, res) => {
    const { user, action, from, to } = req.query;
    res.json(audit.queryLogs({ user, action, from, to }));
  });

  app.get('/api/admin/logs/export', (req, res) => {
    const { user, action, from, to } = req.query;
    const rows = audit.queryLogs({ user, action, from, to });
    audit.log({ user: req.user.login, ip: req.ip, action: 'LOG_EXPORT', description: `Wyeksportowano dziennik zdarzeń (${rows.length} wpisów).`, result: 'sukces' });
    const header = 'id,timestamp,user,ip,action,description,result,hash';
    const csvCell = v => `"${String(v ?? '').replace(/"/g, '""')}"`;
    const csv = [header, ...rows.map(r => [r.id, r.timestamp, r.user, r.ip, r.action, r.description, r.result, r.hash].map(csvCell).join(','))].join('\n');
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="dziennik-zdarzen.csv"');
    res.send(csv);
  });

  app.post('/api/admin/logs/verify', (req, res) => {
    const verification = audit.verifyIntegrity();
    audit.log({
      user: req.user.login,
      ip: req.ip,
      action: 'LOG_VERIFY',
      description: verification.valid ? `Weryfikacja integralności: OK (${verification.checked} wpisów).` : `Wykryto naruszenie integralności w wpisie #${verification.corruptedId}.`,
      result: verification.valid ? 'sukces' : 'błąd'
    });
    res.json(verification);
  });

  app.get('/api/admin/alerts', (req, res) => {
    res.json(audit.getAlerts());
  });

  app.post('/api/admin/alerts/:id/ack', (req, res) => {
    audit.ackAlert(Number(req.params.id));
    res.json({ message: 'Potwierdzono alert.' });
  });
}