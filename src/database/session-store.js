import session from 'express-session';

export function createSessionStore(db) {
  class SQLiteStore extends session.Store {
    get(sid, cb) { try { const r = db.prepare('SELECT data FROM sessions WHERE sid=? AND expires>?').get(sid, Date.now()); cb(null, r ? JSON.parse(r.data) : null); } catch(e) { cb(e); } }
    set(sid, s, cb) { try { db.prepare('INSERT OR REPLACE INTO sessions VALUES (?,?,?,?)').run(sid, JSON.stringify(s), Date.now() + 86400000, s.userId ?? null); cb?.(); } catch(e) { cb?.(e); } }
    destroy(sid, cb) { try { db.prepare('DELETE FROM sessions WHERE sid=?').run(sid); cb?.(); } catch(e) { cb?.(e); } }
    touch(sid, s, cb) { this.set(sid, s, cb); }
  }
  return new SQLiteStore();
}
