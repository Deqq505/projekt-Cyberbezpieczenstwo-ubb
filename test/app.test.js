import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, mkdirSync, rmSync } from 'node:fs';
import path from 'node:path';
import { createApp } from '../src/app.js';

test('Wariant 10 — logowanie, hasła, RBAC, administracja i sesje', async t => {
  mkdirSync('tmp', { recursive: true });
  const dataDir = mkdtempSync(path.resolve('tmp', 'portal-test-'));
  const { app, db, close, initialAdminPassword } = await createApp({ dataDir });
  const server = app.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  const base = `http://127.0.0.1:${server.address().port}/api`;
  const accounts = Object.fromEntries(readFileSync(path.join(dataDir, 'pierwsze-logowanie.txt'), 'utf8').split('\n').filter(l => /^[A-Za-z]+\s+\S+-\d{2}$/.test(l)).map(l => l.trim().split(/\s+/)));
  function client() {
    return { cookie: '', csrf: '', async call(url, method = 'GET', body, headers = {}) {
      const r = await fetch(base + url, { method, headers: { 'Content-Type': 'application/json', Cookie: this.cookie, 'X-CSRF-Token': this.csrf, ...headers }, body: body === undefined ? undefined : JSON.stringify(body) });
      const cookie = r.headers.get('set-cookie'); if (cookie) this.cookie = cookie.split(';')[0];
      const data = await r.json(); if (data.csrf) this.csrf = data.csrf;
      return { status: r.status, data };
    } };
  }
  const admin = client(), reader = client(), worker = client(), editor = client(), manager = client();
  const permanent = 'Bursztynowy!Szlak#86';
  async function activate(c, login) {
    assert.equal((await c.call('/login','POST',{ login, password: accounts[login] })).status, 200);
    assert.equal((await c.call('/password','POST',{ oldPassword: accounts[login], newPassword: permanent, confirmation: permanent })).status, 200);
    assert.equal((await c.call('/login','POST',{ login, password: permanent })).status, 200);
  }
  try {
    await t.test('8 kont: ADMIN + 7 testowych, hashe Argon2id i poprawne OTP', async () => {
      assert.equal(db.prepare('SELECT COUNT(*) AS n FROM users').get().n, 8);
      assert.equal(Object.keys(accounts).length, 8);
      assert.equal(initialAdminPassword, accounts.ADMIN);
      for (const u of db.prepare('SELECT * FROM users').all()) { assert.match(u.password_hash, /^\$argon2id\$/); assert.match(accounts[u.login], /^[a-z]+-[a-z]+-[a-z]+-\d{2}$/); assert.ok(Math.abs(u.otp_expires_at - u.created_at - 12*3600000) < 100); }
    });
    await t.test('restart wyświetla nadal ważne hasło startowe ADMIN, ale nie wygasłe', async () => {
      const restarted = await createApp({ dataDir });
      try { assert.equal(restarted.initialAdminPassword, accounts.ADMIN); }
      finally { restarted.close(); }
      const admin = db.prepare("SELECT id,otp_expires_at FROM users WHERE login='ADMIN'").get();
      db.prepare('UPDATE users SET otp_expires_at=? WHERE id=?').run(Date.now()-1, admin.id);
      const expired = await createApp({ dataDir });
      try { assert.equal(expired.initialAdminPassword, null); }
      finally { expired.close(); }
      db.prepare('UPDATE users SET otp_expires_at=? WHERE id=?').run(admin.otp_expires_at, admin.id);
    });
    await t.test('jednolity błąd logowania, ochrona Origin, blokada panelu przed zmianą hasła', async () => {
      const a = await admin.call('/login','POST',{ login: 'ADMIN', password: 'zle' });
      const b = await admin.call('/login','POST',{ login: 'nieistnieje', password: 'zle' });
      assert.deepEqual(a, b); assert.equal(a.status, 401); assert.equal(a.data.message, 'Login lub hasło niepoprawne');
      assert.equal((await admin.call('/login','POST',{ login: 'ADMIN', password: accounts.ADMIN },{ Origin:'https://inna-strona.example' })).status,403);
      assert.equal((await admin.call('/login','POST',{ login:'ADMIN',password:accounts.ADMIN })).data.mustChange,true);
      assert.equal((await admin.call('/admin/users')).status,403);
      assert.equal((await admin.call('/notes')).status,403);
    });
    await t.test('wymagane stare hasło, potwierdzenie, długość, słownik i CSRF', async () => {
      const change = (p, confirm = p, old = accounts.ADMIN, headers) => admin.call('/password','POST',{ oldPassword:old,newPassword:p,confirmation:confirm }, headers);
      assert.equal((await change(permanent, permanent, 'zle')).status,400);
      assert.equal((await change(permanent, 'inne')).status,400);
      assert.equal((await change('Krotkie#12')).status,400);
      assert.equal((await change('PAZDZIERNIK!987654')).status,400);
      assert.equal((await change('Portal Zespolu!987654')).status,400);
      assert.equal((await change(permanent, permanent, accounts.ADMIN, { 'X-CSRF-Token':'zly' })).status,403);
      assert.equal((await change(permanent)).status,200);
      assert.equal((await admin.call('/session')).status,401);
      assert.equal((await admin.call('/login','POST',{login:'ADMIN',password:permanent})).status,200);
    });
    await t.test('historia haseł oraz aktywacja czterech ról', async () => {
      const r = await admin.call('/password','POST',{oldPassword:permanent,newPassword:accounts.ADMIN,confirmation:accounts.ADMIN});
      assert.equal(r.status,400);
      assert.equal((await admin.call('/password','POST',{oldPassword:permanent,newPassword:permanent,confirmation:permanent})).status,400);
      await activate(reader,'jan'); await activate(worker,'piotr'); await activate(editor,'marek'); await activate(manager,'anna');
    });
    let workerNote;
    await t.test('RBAC: czytelnik, własność szkiców, redakcja, publikacja i HTTP 403', async () => {
      assert.equal((await reader.call('/admin/users')).status,403);
      assert.equal((await reader.call('/notes','POST',{title:'Test',body:'Treść'})).status,403);
      assert.ok((await reader.call('/notes')).data.every(n => n.published));
      assert.equal((await worker.call('/notes')).data.filter(n=>!n.published).length,0);
      const r = await worker.call('/notes','POST',{title:'Szkic pracownika',body:'Treść testowa'}); assert.equal(r.status,201); workerNote = r.data.id;
      assert.equal((await worker.call(`/notes/${workerNote}`,'PUT',{title:'Zmiana',body:'Treść'})).status,200);
      assert.equal((await worker.call('/notes/2','PUT',{title:'Cudzy szkic',body:'Treść'})).status,403);
      assert.equal((await editor.call(`/notes/${workerNote}`,'PUT',{title:'Redakcja',body:'Treść'})).status,200);
      assert.equal((await editor.call(`/notes/${workerNote}/publish`,'POST',{published:true})).status,403);
      assert.equal((await manager.call(`/notes/${workerNote}/publish`,'POST',{published:true})).status,200);
      assert.ok((await reader.call('/notes')).data.some(n => n.id === workerNote));
      assert.equal((await editor.call(`/notes/${workerNote}`,'DELETE')).status,403);
      assert.equal((await manager.call(`/notes/${workerNote}/publish`,'POST',{published:false})).status,200);
      assert.equal((await editor.call(`/notes/${workerNote}`,'DELETE')).status,200);
    });
    await t.test('CRUD kont, duplikaty, ochrona ADMIN, blokada unieważnia sesję', async () => {
      const r = await admin.call('/admin/users','POST',{login:'testowy',name:'Użytkownik Testowy',role:'Czytelnik'}); assert.equal(r.status,201);
      assert.match(r.data.password,/^[a-z]+-[a-z]+-[a-z]+-\d{2}$/);
      assert.equal((await admin.call('/admin/users','POST',{login:'TESTOWY',name:'Test Dwa',role:'Czytelnik'})).status,409);
      assert.equal((await admin.call('/admin/users/1','DELETE')).status,400);
      assert.equal((await admin.call('/admin/users/1','PUT',{login:'inny',name:'Admin',role:'Administrator',blocked:false})).status,400);
      const piotr = (await admin.call('/admin/users')).data.find(u => u.login==='piotr');
      assert.equal((await admin.call(`/admin/users/${piotr.id}`,'PUT',{...piotr,blocked:true})).status,200);
      assert.equal((await worker.call('/notes')).status,401);
      assert.equal((await admin.call(`/admin/users/${r.data.id}`,'DELETE')).status,200);
    });
    await t.test('reset hasła, wygaśnięcie OTP i unieważnienie aktywnej sesji', async () => {
      const jan = db.prepare("SELECT id FROM users WHERE login='jan'").get();
      const r = await admin.call(`/admin/users/${jan.id}/reset`,'POST'); assert.equal(r.status,200);
      assert.equal((await reader.call('/notes')).status,401);
      db.prepare('UPDATE users SET otp_expires_at=? WHERE id=?').run(Date.now()-1,jan.id);
      assert.equal((await reader.call('/login','POST',{login:'jan',password:r.data.password})).status,401);
    });
    await t.test('ustawienia słownika i wygasające hasło', async () => {
      const s = (await admin.call('/session')).data.settings;
      const updated = await admin.call('/admin/settings','PUT',{...s,bannedWords:['Organizacja','Zima'],policyEnabled:true,passwordDays:1,idleMinutes:1}); assert.equal(updated.status,200);
      const marek = db.prepare("SELECT id FROM users WHERE login='marek'").get();
      db.prepare('UPDATE users SET password_changed_at=? WHERE id=?').run(Date.now()-2*86400000,marek.id);
      assert.equal((await editor.call('/notes')).status,403);
      assert.equal((await editor.call('/session')).data.mustChange,true);
      assert.equal((await editor.call('/password','POST',{oldPassword:permanent,newPassword:'ORGANIZACJA#123456',confirmation:'ORGANIZACJA#123456'})).status,400);
      assert.equal((await admin.call('/admin/settings','PUT',{...s,policyEnabled:false})).status,200);
      assert.equal((await editor.call('/password','POST',{oldPassword:permanent,newPassword:'ORGANIZACJA#123456',confirmation:'ORGANIZACJA#123456'})).status,200);
    });
    await t.test('wygaśnięcie sesji jest egzekwowane na serwerze, wylogowanie niszczy sesję', async () => {
      const anna = db.prepare("SELECT id FROM users WHERE login='anna'").get();
      const row = db.prepare('SELECT * FROM sessions WHERE user_id=?').get(anna.id);
      const s = JSON.parse(row.data); s.lastSeen = Date.now() - 16*60000;
      db.prepare('UPDATE sessions SET data=? WHERE sid=?').run(JSON.stringify(s),row.sid);
      const r = await manager.call('/notes'); assert.equal(r.status,401); assert.equal(r.data.reason,'idle');
      const cookie = admin.cookie; assert.equal((await admin.call('/logout','POST')).status,200);
      admin.cookie = cookie; assert.equal((await admin.call('/admin/users')).status,401);
    });
    await t.test('ponowne uruchomienie zachowuje konta i nie ujawnia hasła startowego', async () => {
      const previousHash = db.prepare("SELECT password_hash FROM users WHERE login='ADMIN'").get().password_hash;
      const restarted = await createApp({ dataDir });
      try {
        assert.equal(restarted.initialAdminPassword, null);
        assert.equal(restarted.db.prepare("SELECT password_hash FROM users WHERE login='ADMIN'").get().password_hash, previousHash);
      } finally { restarted.close(); }
    });
  } finally {
    await new Promise(resolve => server.close(resolve)); close();
    rmSync(dataDir,{recursive:true,force:true});
  }
});
