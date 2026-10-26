import argon2 from 'argon2';
import { randomBytes } from 'node:crypto';
import { hash, normalize } from '../services/passwords.js';
import { fail } from '../utils/http.js';

export async function registerAuthRoutes(app, { db, getSettings, requireAuth, publicSession }) {
  const attempts = new Map();
  const dummy = await hash(randomBytes(24).toString('hex'));
  app.post('/api/login', async (req, res) => {
    const { login, password } = req.body ?? {};
    if (typeof login !== 'string' || typeof password !== 'string' || login.length > 40 || password.length > 1024) return fail(res, 400, 'Login lub hasło niepoprawne');
    const key = req.ip;
    let attempt = attempts.get(key);
    if (!attempt || attempt.until < Date.now()) { attempt = { count: 0, until: Date.now() + 60000 }; attempts.set(key, attempt); }
    if (++attempt.count > 20) return fail(res, 429, 'Zbyt wiele prób. Spróbuj ponownie za minutę.');
    const u = db.prepare('SELECT * FROM users WHERE login=?').get(login.trim());
    const valid = await argon2.verify(u?.password_hash ?? dummy, password);
    if (!u || !valid || u.blocked || (u.must_change && u.otp_expires_at <= Date.now())) return fail(res, 401, 'Login lub hasło niepoprawne');
    req.session.regenerate(err => {
      if (err) return fail(res, 500, 'Nie udało się utworzyć sesji.');
      req.session.userId = u.id; req.session.csrf = randomBytes(32).toString('hex'); req.session.lastSeen = Date.now();
      req.user = u; req.config = getSettings(); req.needsChange = Boolean(u.must_change) || (req.config.passwordDays > 0 && Date.now() - u.password_changed_at >= req.config.passwordDays * 86400000);
      res.json(publicSession(req));
    });
  });
  app.get('/api/session', requireAuth, (req, res) => res.json(publicSession(req)));
  app.post('/api/activity', requireAuth, (req, res) => res.json({ idleExpiresAt: req.session.lastSeen + req.config.idleMinutes * 60000 }));
  app.post('/api/logout', requireAuth, (req, res) => req.session.destroy(() => { res.clearCookie('portal.sid'); res.json({ message: 'Wylogowano.' }); }));
  app.post('/api/password', requireAuth, async (req, res) => {
    const { oldPassword, newPassword, confirmation } = req.body ?? {};
    if (![oldPassword,newPassword,confirmation].every(v => typeof v === 'string' && v.length <= 1024)) return fail(res, 400, 'Uzupełnij poprawnie wszystkie pola.');
    if (!await argon2.verify(req.user.password_hash, oldPassword)) return fail(res, 400, 'Stare hasło jest niepoprawne.');
    if (newPassword !== confirmation) return fail(res, 400, 'Nowe hasła muszą być identyczne.');
    if ([...newPassword].length < req.config.minLength) return fail(res, 400, `Hasło musi mieć co najmniej ${req.config.minLength} znaków.`);
    if (req.config.policyEnabled && req.config.bannedWords.some(word => normalize(newPassword).includes(normalize(word)))) return fail(res, 400, 'Hasło zawiera słowo ze słownika zakazanych.');
    const common = ['12345678901234', '123456789012345', 'qwertyuiopasdfgh', 'passwordpassword', 'haslohaslohaslo', 'abcdefghijklmn'];
    if (common.includes(normalize(newPassword)) || /^(.)\1+$/u.test(newPassword)) return fail(res, 400, 'To hasło jest zbyt popularne. Wybierz inne.');
    const history = db.prepare('SELECT hash FROM password_history WHERE user_id=?').all(req.user.id);
    for (const h of [{ hash: req.user.password_hash }, ...history]) if (await argon2.verify(h.hash, newPassword)) return fail(res, 400, 'Nie możesz ponownie użyć poprzedniego hasła.');
    const newHash = await hash(newPassword);
    db.exec('BEGIN');
    try {
      db.prepare('INSERT INTO password_history (user_id,hash) VALUES (?,?)').run(req.user.id, req.user.password_hash);
      db.prepare('UPDATE users SET password_hash=?,must_change=0,otp_expires_at=NULL,password_changed_at=? WHERE id=?').run(newHash, Date.now(), req.user.id);
      db.prepare('DELETE FROM sessions WHERE user_id=?').run(req.user.id);
      db.exec('COMMIT');
    } catch(e) { db.exec('ROLLBACK'); throw e; }
    req.session.destroy(() => { res.clearCookie('portal.sid'); res.json({ message: 'Hasło zostało zmienione. Zaloguj się nowym hasłem.' }); });
  });
  return attempts;
}
