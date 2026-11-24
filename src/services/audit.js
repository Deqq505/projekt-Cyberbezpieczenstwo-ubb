import { createHash } from 'node:crypto';

const clean = v => String(v ?? '').replace(/[\r\n\x00-\x1f\x7f]/g, ' ').trim().slice(0, 500);

function computeHash(entry, prevHash) {
  const payload = [
    entry.timestamp,
    entry.user,
    entry.ip,
    entry.action,
    entry.description,
    entry.result,
    prevHash
  ].join('|');
  return createHash('sha512').update(payload).digest('hex');
}

export function createAudit(db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS security_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      timestamp TEXT NOT NULL,
      user TEXT NOT NULL,
      ip TEXT NOT NULL,
      action TEXT NOT NULL,
      description TEXT NOT NULL,
      result TEXT NOT NULL,
      prev_hash TEXT NOT NULL,
      hash TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS security_alerts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      timestamp TEXT NOT NULL,
      rule TEXT NOT NULL,
      message TEXT NOT NULL,
      user TEXT NOT NULL,
      acknowledged INTEGER NOT NULL DEFAULT 0
    );
  `);

  function insertLog({ user, ip, action, description, result }) {
    const timestamp = new Date().toISOString();
    const entry = {
      timestamp,
      user: clean(user || 'anonim'),
      ip: clean(ip || 'unknown'),
      action: clean(action),
      description: clean(description),
      result: clean(result)
    };
    const last = db.prepare('SELECT hash FROM security_logs ORDER BY id DESC LIMIT 1').get();
    const prevHash = last ? last.hash : 'GENESIS';
    const hash = computeHash(entry, prevHash);
    db.prepare(
      'INSERT INTO security_logs (timestamp,user,ip,action,description,result,prev_hash,hash) VALUES (?,?,?,?,?,?,?,?)'
    ).run(entry.timestamp, entry.user, entry.ip, entry.action, entry.description, entry.result, prevHash, hash);
    return entry;
  }

  function createAlert(rule, message, user, ip) {
    const timestamp = new Date().toISOString();
    db.prepare(
      'INSERT INTO security_alerts (timestamp,rule,message,user) VALUES (?,?,?,?)'
    ).run(timestamp, clean(rule), clean(message), clean(user));
    insertLog({ user: 'SYSTEM', ip: ip || '127.0.0.1', action: 'ALERT', description: `[${rule}] ${message}`, result: 'alert' });
  }

  function log(params) {
    const entry = insertLog(params);

    if (entry.action === 'LOGIN_FAIL' && entry.user !== 'anonim') {
      const since = new Date(Date.now() - 5 * 60 * 1000).toISOString();
      const { cnt } = db.prepare(
        "SELECT COUNT(*) AS cnt FROM security_logs WHERE action='LOGIN_FAIL' AND user=? AND timestamp>=?"
      ).get(entry.user, since);
      if (cnt >= 5) {
        const exists = db.prepare(
          "SELECT id FROM security_alerts WHERE rule='BRUTE_FORCE' AND user=? AND timestamp>=?"
        ).get(entry.user, since);
        if (!exists) {
          createAlert('BRUTE_FORCE', `Wykryto ${cnt} nieudanych logowań na konto ${entry.user} w ciągu 5 minut.`, entry.user, entry.ip);
        }
      }
    }

    if ((entry.action === 'USER_DELETE' || entry.action === 'USER_BLOCK') && entry.result === 'sukces') {
      const since = new Date(Date.now() - 10 * 60 * 1000).toISOString();
      const { cnt } = db.prepare(
        "SELECT COUNT(*) AS cnt FROM security_logs WHERE action IN ('USER_DELETE','USER_BLOCK') AND result='sukces' AND user=? AND timestamp>=?"
      ).get(entry.user, since);
      if (cnt >= 3) {
        const exists = db.prepare(
          "SELECT id FROM security_alerts WHERE rule='MASS_ACCOUNT_ACTION' AND user=? AND timestamp>=?"
        ).get(entry.user, since);
        if (!exists) {
          createAlert('MASS_ACCOUNT_ACTION', `Administrator ${entry.user} usunął lub zablokował ${cnt} kont w ciągu 10 minut.`, entry.user, entry.ip);
        }
      }
    }

    return entry;
  }

  function verifyIntegrity() {
    const rows = db.prepare('SELECT * FROM security_logs ORDER BY id ASC').all();
    let expectedPrev = 'GENESIS';
    for (const row of rows) {
      if (row.prev_hash !== expectedPrev) {
        return { valid: false, checked: rows.length, corruptedId: row.id, reason: 'Przerwany łańcuch skrótów (usunięty lub zmodyfikowany poprzedni wpis).' };
      }
      const recalculated = computeHash(row, expectedPrev);
      if (row.hash !== recalculated) {
        return { valid: false, checked: rows.length, corruptedId: row.id, reason: 'Niezgodny skrót SHA-512 (zmodyfikowano treść wpisu).' };
      }
      expectedPrev = row.hash;
    }
    return { valid: true, checked: rows.length };
  }

  function queryLogs({ user, action, from, to } = {}) {
    const where = [], args = [];
    if (user) { where.push('LOWER(user) LIKE ?'); args.push(`%${user.toLowerCase()}%`); }
    if (action) { where.push('action=?'); args.push(action); }
    if (from) { where.push('timestamp>=?'); args.push(from); }
    if (to) { where.push('timestamp<=?'); args.push(to.length === 10 ? `${to}T23:59:59.999Z` : to); }
    const sql = `SELECT * FROM security_logs ${where.length ? 'WHERE ' + where.join(' AND ') : ''} ORDER BY id DESC LIMIT 500`;
    return db.prepare(sql).all(...args);
  }

  function getAlerts() {
    return db.prepare('SELECT * FROM security_alerts ORDER BY id DESC LIMIT 50').all();
  }

  function ackAlert(id) {
    db.prepare('UPDATE security_alerts SET acknowledged=1 WHERE id=?').run(id);
  }

  return { log, verifyIntegrity, queryLogs, getAlerts, ackAlert };
}