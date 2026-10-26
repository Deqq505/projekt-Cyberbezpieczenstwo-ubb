import { fail } from '../utils/http.js';
import { safeUser } from '../utils/user.js';

export function createAuth({ db, getSettings }) {
  const requireAuth = (req, res, next) => {
    const u = req.session.userId && db.prepare('SELECT * FROM users WHERE id=?').get(req.session.userId);
    if (!u || u.blocked) { req.session.destroy(() => {}); return fail(res, 401, 'Zaloguj się ponownie.'); }
    const s = getSettings();
    if (Date.now() - req.session.lastSeen >= s.idleMinutes * 60000) { req.session.destroy(() => {}); return fail(res, 401, 'Sesja wygasła z powodu bezczynności.', { reason: 'idle' }); }
    if (u.must_change && u.otp_expires_at <= Date.now()) { req.session.destroy(() => {}); return fail(res, 401, 'Hasło jednorazowe wygasło. Poproś administratora o reset.'); }
    if (req.path !== '/session') req.session.lastSeen = Date.now();
    if (!['GET','HEAD'].includes(req.method) && req.get('X-CSRF-Token') !== req.session.csrf) return fail(res, 403, 'Nieprawidłowy token żądania. Odśwież stronę.');
    req.user = u; req.config = s;
    req.needsChange = Boolean(u.must_change) || (s.passwordDays > 0 && Date.now() - u.password_changed_at >= s.passwordDays * 86400000);
    next();
  };
  const currentPassword = (req, res, next) => req.needsChange ? fail(res, 403, 'Najpierw zmień hasło.', { reason: 'password_change' }) : next();
  const admin = (req, res, next) => req.user.role === 'Administrator' ? next() : fail(res, 403, 'Brak uprawnień do tej operacji.');
  const publicSession = req => ({ user: safeUser(req.user), mustChange: req.needsChange, csrf: req.session.csrf, settings: req.config, idleExpiresAt: req.session.lastSeen + req.config.idleMinutes * 60000 });
  return { requireAuth, currentPassword, admin, publicSession };
}
