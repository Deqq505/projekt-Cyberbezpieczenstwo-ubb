import { DatabaseSync } from 'node:sqlite';
import { mkdirSync, writeFileSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { hash, otp } from '../services/passwords.js';
import argon2 from 'argon2';

export async function createDatabase(dataDir) {
  let initialAdminPassword = null;
  mkdirSync(dataDir, { recursive: true });
  const db = new DatabaseSync(path.join(dataDir, 'portal.sqlite'));
  db.exec(readFileSync(new URL('./schema.sql', import.meta.url), 'utf8'));
  db.prepare('INSERT OR IGNORE INTO settings VALUES (1,1,14,0,15,?)').run(JSON.stringify(['Portal zespołu', 'uczelnia', 'firma', 'styczeń', 'luty', 'marzec', 'kwiecień', 'maj', 'czerwiec', 'lipiec', 'sierpień', 'wrzesień', 'październik', 'listopad', 'grudzień', 'wiosna', 'lato', 'jesień', 'zima']));
  const getSettings = () => { const s = db.prepare('SELECT * FROM settings WHERE id=1').get(); return { policyEnabled: Boolean(s.policy_enabled), minLength: s.min_length, passwordDays: s.password_days, idleMinutes: s.idle_minutes, bannedWords: JSON.parse(s.banned_words) }; };
  async function addUser(login, name, role) {
    const password = otp(), passwordHash = await hash(password), now = Date.now();
    const result = db.prepare('INSERT INTO users (login,name,role,password_hash,otp_expires_at,password_changed_at,created_at) VALUES (?,?,?,?,?,?,?)').run(login, name, role, passwordHash, now + 12 * 3600000, now, now);
    return { id: Number(result.lastInsertRowid), login, password, expiresAt: now + 12 * 3600000 };
  }
  if (!db.prepare('SELECT id FROM users LIMIT 1').get()) {
    const accounts = [];
    for (const [login, name, role] of [['ADMIN','Administrator','Administrator'],['anna','Anna Kowalska','Kierownik'],['marek','Marek Nowak','Redaktor'],['ewa','Ewa Wiśniewska','Redaktor'],['piotr','Piotr Wójcik','Pracownik'],['ola','Aleksandra Kamińska','Pracownik'],['jan','Jan Lewandowski','Czytelnik'],['zofia','Zofia Zielińska','Czytelnik']]) accounts.push(await addUser(login, name, role));
    initialAdminPassword = accounts[0].password;
    writeFileSync(path.join(dataDir, 'pierwsze-logowanie.txt'), 'KONTA POCZĄTKOWE — WARIANT 10\nHasła jednorazowe: ważne 12 godzin od utworzenia bazy.\nPo pierwszym logowaniu ustaw własne hasło (minimum 14 znaków).\nPo zapisaniu własnych haseł usuń ten plik.\n\n' + accounts.map(a => `${a.login.padEnd(10)} ${a.password}`).join('\n'), 'utf8');
    db.prepare('INSERT INTO notes (title,body,owner_id,published,updated_at) VALUES (?,?,?,?,?)').run('Witaj w portalu zespołu', 'To wspólna przestrzeń na notatki. Zakres dostępnych działań zależy od roli przypisanej do Twojego konta.', accounts[1].id, 1, Date.now());
    db.prepare('INSERT INTO notes (title,body,owner_id,published,updated_at) VALUES (?,?,?,?,?)').run('Notatka robocza', 'Ten szkic jest widoczny dla autora, redaktorów, kierowników i administratora. Publikację zatwierdza kierownik lub administrator.', accounts[3].id, 0, Date.now());
  }
  if (!initialAdminPassword) {
    const admin = db.prepare("SELECT * FROM users WHERE login='ADMIN'").get();
    if (admin?.must_change && !admin.blocked && admin.otp_expires_at > Date.now()) {
      try {
        const content = readFileSync(path.join(dataDir, 'pierwsze-logowanie.txt'), 'utf8');
        const candidate = content.match(/^ADMIN[\t ]+(\S+)[\t ]*$/m)?.[1];
        if (candidate && await argon2.verify(admin.password_hash, candidate)) initialAdminPassword = candidate;
      } catch (error) {
        if (error.code !== 'ENOENT') throw error;
      }
    }
  }
  return { db, getSettings, addUser, initialAdminPassword };
}
