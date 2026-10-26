import express from 'express';
import session from 'express-session';
import { randomBytes } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { DATA_DIR, PUBLIC_DIR } from './config/paths.js';
import { createDatabase } from './database/index.js';
import { createSessionStore } from './database/session-store.js';
import { createAuth } from './middleware/auth.js';
import { registerAuthRoutes } from './routes/auth.js';
import { registerAdminRoutes } from './routes/admin.js';
import { registerNoteRoutes } from './routes/notes.js';
import { fail } from './utils/http.js';

export async function createApp({ dataDir = DATA_DIR } = {}) {
  const database = await createDatabase(dataDir);
  const { db } = database;
  const secretPath = path.join(dataDir, 'session-secret');
  if (!existsSync(secretPath)) writeFileSync(secretPath, randomBytes(48).toString('hex'), { mode: 0o600 });
  const app = express();
  app.disable('x-powered-by');
  app.use((req, res, next) => { res.set({ 'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'", 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'same-origin' }); next(); });
  app.use(express.json({ limit: '32kb' }));
  app.use(session({ name: 'portal.sid', secret: readFileSync(secretPath, 'utf8'), store: createSessionStore(db), resave: false, saveUninitialized: false, cookie: { httpOnly: true, sameSite: 'strict', secure: process.env.HTTPS === '1', maxAge: 86400000 } }));
  app.use('/api', (req, res, next) => {
    res.set('Cache-Control', 'no-store');
    if (!['GET','HEAD'].includes(req.method) && req.headers.origin && req.headers.origin !== `${req.protocol}://${req.get('host')}`) return res.status(403).json({ message: 'Niedozwolone źródło żądania.' });
    next();
  });
  const context = { ...database, ...createAuth(database) };
  const attempts = await registerAuthRoutes(app, context);
  registerAdminRoutes(app, context);
  registerNoteRoutes(app, context);
  app.use('/api', (req,res) => fail(res,404,'Nie znaleziono zasobu.'));
  app.use(express.static(PUBLIC_DIR));
  app.use((err, req, res, next) => { console.error(err.message); fail(res, err.type === 'entity.parse.failed' ? 400 : 500, err.type === 'entity.parse.failed' ? 'Nieprawidłowe dane JSON.' : 'Nie udało się wykonać operacji.'); });
  const cleanup = setInterval(() => { db.prepare('DELETE FROM sessions WHERE expires<?').run(Date.now()); for (const [k,v] of attempts) if (v.until < Date.now()) attempts.delete(k); }, 60000);
  cleanup.unref();
  return { app, db, initialAdminPassword: database.initialAdminPassword, close: () => { clearInterval(cleanup); db.close(); } };
}

