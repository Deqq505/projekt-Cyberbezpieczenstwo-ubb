import { fail } from '../utils/http.js';

export function registerNoteRoutes(app, { db, requireAuth, currentPassword }) {
  const editors = ['Administrator','Kierownik','Redaktor'];
  const publishers = ['Administrator','Kierownik'];
  app.use('/api/notes', requireAuth, currentPassword);
  app.get('/api/notes', (req, res) => res.json(db.prepare(`SELECT notes.*, users.name AS author FROM notes LEFT JOIN users ON users.id=notes.owner_id WHERE published=1 OR owner_id=? OR ?=1 ORDER BY updated_at DESC`).all(req.user.id, Number(editors.includes(req.user.role))).map(n => ({ ...n, canEdit: !n.published && (editors.includes(req.user.role) || (req.user.role === 'Pracownik' && n.owner_id === req.user.id)), canPublish: publishers.includes(req.user.role) }))));
  const validNote = b => b && typeof b.title === 'string' && b.title.trim().length > 0 && b.title.length <= 120 && typeof b.body === 'string' && b.body.trim().length > 0 && b.body.length <= 5000;
  app.post('/api/notes', (req, res) => {
    if (req.user.role === 'Czytelnik') return fail(res, 403, 'Brak uprawnień do tworzenia notatek.');
    if (!validNote(req.body)) return fail(res, 400, 'Podaj tytuł (do 120 znaków) i treść (do 5000 znaków).');
    const r = db.prepare('INSERT INTO notes (title,body,owner_id,updated_at) VALUES (?,?,?,?)').run(req.body.title.trim(), req.body.body.trim(), req.user.id, Date.now());
    res.status(201).json({ id: Number(r.lastInsertRowid) });
  });
  app.put('/api/notes/:id', (req, res) => {
    const n = db.prepare('SELECT * FROM notes WHERE id=?').get(req.params.id);
    if (!n || n.published || !(editors.includes(req.user.role) || (req.user.role === 'Pracownik' && n.owner_id === req.user.id))) return fail(res, 403, 'Brak uprawnień do edycji tej notatki.');
    if (!validNote(req.body)) return fail(res, 400, 'Podaj tytuł (do 120 znaków) i treść (do 5000 znaków).');
    db.prepare('UPDATE notes SET title=?,body=?,updated_at=? WHERE id=?').run(req.body.title.trim(), req.body.body.trim(), Date.now(), n.id);
    res.json({ message: 'Zapisano notatkę.' });
  });
  app.delete('/api/notes/:id', (req, res) => {
    const n = db.prepare('SELECT * FROM notes WHERE id=?').get(req.params.id);
    if (!n || n.published || !(editors.includes(req.user.role) || (req.user.role === 'Pracownik' && n.owner_id === req.user.id))) return fail(res, 403, 'Brak uprawnień do usunięcia tej notatki.');
    db.prepare('DELETE FROM notes WHERE id=?').run(n.id); res.json({ message: 'Usunięto notatkę.' });
  });
  app.post('/api/notes/:id/publish', (req, res) => {
    if (!publishers.includes(req.user.role)) return fail(res, 403, 'Publikować może kierownik lub administrator.');
    if (typeof req.body.published !== 'boolean') return fail(res, 400, 'Nieprawidłowy stan publikacji.');
    const r = db.prepare('UPDATE notes SET published=?,updated_at=? WHERE id=?').run(Number(req.body.published), Date.now(), req.params.id);
    if (!r.changes) return fail(res, 404, 'Nie znaleziono notatki.');
    res.json({ message: req.body.published ? 'Opublikowano notatkę.' : 'Przeniesiono do szkiców.' });
  });
}
