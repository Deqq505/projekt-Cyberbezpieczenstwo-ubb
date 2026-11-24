import argon2 from 'argon2';
import { randomBytes } from 'node:crypto';
import rateLimit from 'express-rate-limit';
import { hash, normalize } from '../services/passwords.js';
import { fail } from '../utils/http.js';

const TURNSTILE_SECRET = process.env.TURNSTILE_SECRET;

async function verifyTurnstile(token, ip) {
  try {
    const res = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `secret=${TURNSTILE_SECRET}&response=${token}&remoteip=${ip}`
    });
    const data = await res.json();
    return data.success;
  } catch (err) {
    return false;
  }
}

export async function registerAuthRoutes(app, { db, getSettings, requireAuth, publicSession, audit }) {
  const dummy = await hash(randomBytes(24).toString('hex'));
  const accountLocks = new Map();

  const ipLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    skipSuccessfulRequests: true,
    message: { message: 'Zbyt wiele prób logowania z tego adresu IP. Spróbuj ponownie za 15 minut.' }
  });

  app.post('/api/login', ipLimiter, async (req, res) => {
    if (req.body.website) {
      audit.log({ user: req.body.login || 'bot', ip: req.ip, action: 'HONEYTOKEN', description: 'Wypełniono ukryte pole formularza logowania.', result: 'błąd' });
      return fail(res, 401, 'Błąd weryfikacji. Odmowa dostępu.');
    }

    const { login, password, turnstile } = req.body ?? {};

    if (!turnstile || typeof turnstile !== 'string') {
      audit.log({ user: login || 'anonim', ip: req.ip, action: 'LOGIN_FAIL', description: 'Brak tokenu CAPTCHA.', result: 'błąd' });
      return fail(res, 400, 'Zaznacz, że nie jesteś robotem (CAPTCHA).');
    }
    const isHuman = await verifyTurnstile(turnstile, req.ip);
    if (!isHuman) {
      audit.log({ user: login || 'anonim', ip: req.ip, action: 'LOGIN_FAIL', description: 'Nieprawidłowy token CAPTCHA.', result: 'błąd' });
      return fail(res, 400, 'Weryfikacja CAPTCHA nie powiodła się.');
    }

    if (typeof login !== 'string' || typeof password !== 'string' || login.length > 40 || password.length > 1024) {
      audit.log({ user: 'anonim', ip: req.ip, action: 'LOGIN_FAIL', description: 'Nieprawidłowy format danych logowania.', result: 'błąd' });
      return fail(res, 400, 'Login lub hasło niepoprawne');
    }

    const cleanLogin = login.trim();

    const lock = accountLocks.get(cleanLogin);
    if (lock && lock.until > Date.now()) {
      const minutesLeft = Math.ceil((lock.until - Date.now()) / 60000);
      audit.log({ user: cleanLogin, ip: req.ip, action: 'LOGIN_FAIL', description: 'Próba logowania na czasowo zablokowane konto.', result: 'błąd' });
      return fail(res, 429, `Konto zablokowane. Spróbuj ponownie za ${minutesLeft} min.`);
    }

    const u = db.prepare('SELECT * FROM users WHERE login=?').get(cleanLogin);
    const valid = await argon2.verify(u?.password_hash ?? dummy, password);

    if (!u || !valid || u.blocked || (u.must_change && u.otp_expires_at <= Date.now())) {
      audit.log({ user: cleanLogin, ip: req.ip, action: 'LOGIN_FAIL', description: 'Nieudana próba logowania.', result: 'błąd' });
      if (u) {
        const attempts = (lock?.count || 0) + 1;
        if (attempts >= 3) {
          accountLocks.set(cleanLogin, { count: attempts, until: Date.now() + 15 * 60 * 1000 });
          audit.log({ user: cleanLogin, ip: req.ip, action: 'ACCOUNT_LOCK', description: 'Konto zablokowane na 15 minut po 3 nieudanych próbach.', result: 'błąd' });
          return fail(res, 429, `Zbyt wiele błędnych prób. Konto zablokowane na 15 minut.`);
        } else {
          accountLocks.set(cleanLogin, { count: attempts, until: 0 });
        }
      }
      return fail(res, 401, 'Login lub hasło niepoprawne');
    }

    accountLocks.delete(cleanLogin);

    req.session.regenerate(err => {
      if (err) return fail(res, 500, 'Nie udało się utworzyć sesji.');
      req.session.userId = u.id; req.session.csrf = randomBytes(32).toString('hex'); req.session.lastSeen = Date.now();
      req.user = u; req.config = getSettings(); req.needsChange = Boolean(u.must_change) || (req.config.passwordDays > 0 && Date.now() - u.password_changed_at >= req.config.passwordDays * 86400000);
      audit.log({ user: u.login, ip: req.ip, action: 'LOGIN', description: 'Poprawne logowanie do systemu.', result: 'sukces' });
      res.json(publicSession(req));
    });
  });

  app.get('/api/session', requireAuth, (req, res) => res.json(publicSession(req)));
  app.post('/api/activity', requireAuth, (req, res) => res.json({ idleExpiresAt: req.session.lastSeen + req.config.idleMinutes * 60000 }));
  app.post('/api/logout', requireAuth, (req, res) => {
    const login = req.user.login;
    req.session.destroy(() => {
      res.clearCookie('portal.sid');
      audit.log({ user: login, ip: req.ip, action: 'LOGOUT', description: 'Wylogowanie z systemu.', result: 'sukces' });
      res.json({ message: 'Wylogowano.' });
    });
  });

  app.post('/api/password', requireAuth, async (req, res) => {
    const { oldPassword, newPassword, confirmation, turnstile } = req.body ?? {};

    if (!turnstile || typeof turnstile !== 'string') {
      audit.log({ user: req.user.login, ip: req.ip, action: 'PASSWORD_CHANGE', description: 'Nieudana zmiana hasła: brak CAPTCHA.', result: 'błąd' });
      return fail(res, 400, 'Zaznacz, że nie jesteś robotem (CAPTCHA).');
    }
    const isHuman = await verifyTurnstile(turnstile, req.ip);
    if (!isHuman) {
      audit.log({ user: req.user.login, ip: req.ip, action: 'PASSWORD_CHANGE', description: 'Nieudana zmiana hasła: błędna CAPTCHA.', result: 'błąd' });
      return fail(res, 400, 'Weryfikacja CAPTCHA nie powiodła się.');
    }

    if (![oldPassword,newPassword,confirmation].every(v => typeof v === 'string' && v.length <= 1024)) return fail(res, 400, 'Uzupełnij poprawnie wszystkie pola.');
    if (!await argon2.verify(req.user.password_hash, oldPassword)) {
      audit.log({ user: req.user.login, ip: req.ip, action: 'PASSWORD_CHANGE', description: 'Nieudana zmiana hasła: błędne obecne hasło.', result: 'błąd' });
      return fail(res, 400, 'Stare hasło jest niepoprawne.');
    }
    if (newPassword !== confirmation) return fail(res, 400, 'Nowe hasła muszą być identyczne.');
    if ([...newPassword].length < req.config.minLength) {
      audit.log({ user: req.user.login, ip: req.ip, action: 'PASSWORD_CHANGE', description: 'Nieudana zmiana hasła: zbyt krótkie hasło.', result: 'błąd' });
      return fail(res, 400, `Hasło musi mieć co najmniej ${req.config.minLength} znaków.`);
    }
    if (req.config.policyEnabled && req.config.bannedWords.some(word => normalize(newPassword).includes(normalize(word)))) {
      audit.log({ user: req.user.login, ip: req.ip, action: 'PASSWORD_CHANGE', description: 'Nieudana zmiana hasła: zakazane słowo.', result: 'błąd' });
      return fail(res, 400, 'Hasło zawiera słowo ze słownika zakazanych.');
    }

    const common = ['12345678901234', '123456789012345', 'qwertyuiopasdfgh', 'passwordpassword', 'haslohaslohaslo', 'abcdefghijklmn'];
    if (common.includes(normalize(newPassword)) || /^(.)\1+$/u.test(newPassword)) {
      audit.log({ user: req.user.login, ip: req.ip, action: 'PASSWORD_CHANGE', description: 'Nieudana zmiana hasła: zbyt popularne.', result: 'błąd' });
      return fail(res, 400, 'To hasło jest zbyt popularne. Wybierz inne.');
    }

    const history = db.prepare('SELECT hash FROM password_history WHERE user_id=?').all(req.user.id);
    for (const h of [{ hash: req.user.password_hash }, ...history]) {
      if (await argon2.verify(h.hash, newPassword)) {
        audit.log({ user: req.user.login, ip: req.ip, action: 'PASSWORD_CHANGE', description: 'Nieudana zmiana hasła: powtórzenie z historii.', result: 'błąd' });
        return fail(res, 400, 'Nie możesz ponownie użyć poprzedniego hasła.');
      }
    }

    const newHash = await hash(newPassword);
    db.exec('BEGIN');
    try {
      db.prepare('INSERT INTO password_history (user_id,hash) VALUES (?,?)').run(req.user.id, req.user.password_hash);
      db.prepare('UPDATE users SET password_hash=?,must_change=0,otp_expires_at=NULL,password_changed_at=? WHERE id=?').run(newHash, Date.now(), req.user.id);
      db.prepare('DELETE FROM sessions WHERE user_id=?').run(req.user.id);
      db.exec('COMMIT');
    } catch(e) { db.exec('ROLLBACK'); throw e; }
    audit.log({ user: req.user.login, ip: req.ip, action: 'PASSWORD_CHANGE', description: 'Zmieniono hasło użytkownika.', result: 'sukces' });
    req.session.destroy(() => { res.clearCookie('portal.sid'); res.json({ message: 'Hasło zostało zmienione. Zaloguj się nowym hasłem.' }); });
  });

  return accountLocks;
}