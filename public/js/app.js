const $ = (s, root = document) => root.querySelector(s);
const app = $('#app'), modal = $('#modal');
let state = null, view = 'notes', users = [], notes = [], idleTimer, toastTimer, lastActivity = 0;
const roles = ['Administrator','Kierownik','Redaktor','Pracownik','Czytelnik'];
const paths = {
  users: '<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2M22 21v-2a4 4 0 0 0-3-3.87"/><circle cx="9" cy="7" r="4"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/>',
  shield: '<path d="m12 3 8 3v6c0 5-8 9-8 9s-8-4-8-9V6z"/><path d="m8 12 3 3 5-6"/>',
  key: '<circle cx="8" cy="8" r="5"/><path d="m12 12 9 9m-4-4 3-3m-6 0 3-3"/>',
  user: '<circle cx="12" cy="7" r="4"/><path d="M4 21v-2a6 6 0 0 1 6-6h4a6 6 0 0 1 6 6v2"/>',
  logout: '<path d="M9 21H4V3h5m5 5 5 4-5 4m-5-4h10"/>',
  notes: '<rect x="4" y="3" width="16" height="18" rx="2"/><path d="M8 8h8M8 12h8M8 16h5"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  edit: '<path d="m16 3 5 5-12 12-6 1 1-6zM13 6l5 5"/>',
  trash: '<path d="M3 6h18M9 6V3h6v3M5 6l1 15h12l1-15M10 10v7M14 10v7"/>',
  search: '<circle cx="10" cy="10" r="6"/><path d="m15 15 5 5"/>',
  eye: '<path d="M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>',
  lock: '<rect x="5" y="10" width="14" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3M12 14v3"/>',
  arrow: '<path d="M4 12h16m-6-6 6 6-6 6"/>',
  close: '<path d="m6 6 12 12M6 18 18 6"/>',
  clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
  check: '<path d="m5 12 4 4L19 6"/>',
};
const icon = name => `<svg viewBox="0 0 24 24" aria-hidden="true">${paths[name] || paths.notes}</svg>`;
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' }[c]));
const initials = s => s.split(' ').map(v => v[0]).slice(0,2).join('').toUpperCase();
const date = n => new Intl.DateTimeFormat('pl', { dateStyle: 'medium', timeStyle: 'short' }).format(n);
const brand = (extra = '') => `<div class="brand ${extra}"><span class="brand-mark">P</span>Portal zespołu</div>`;
const passwordField = (name, label, autocomplete = 'new-password') => `<div class="field"><label for="${name}">${label}</label><div class="input-wrap"><input type="password" id="${name}" name="${name}" autocomplete="${autocomplete}" required maxlength="1024" placeholder="Wpisz hasło"><button class="icon-btn" type="button" data-show="${name}" aria-label="Pokaż hasło">${icon('eye')}</button></div></div>`;
function toast(text, error = false) { const el = $('#toast'); el.textContent = text; el.className = error ? 'error-toast' : ''; el.hidden = false; clearTimeout(toastTimer); toastTimer = setTimeout(() => el.hidden = true, 5000); }
function setError(form, message) { const el = $('.error', form); el.textContent = message; el.hidden = !message; }
async function api(url, method = 'GET', body) {
  const response = await fetch(`/api${url}`, { method, headers: { 'Content-Type': 'application/json', ...(state ? { 'X-CSRF-Token': state.csrf } : {}) }, body: body === undefined ? undefined : JSON.stringify(body) });
  const result = await response.json();
  if (!response.ok) {
    if (response.status === 401 && state) { state = null; clearTimeout(idleTimer); modal.close(); renderLogin(result.message); }
    if (result.reason === 'password_change' && state) { state.mustChange = true; renderChange(); }
    throw new Error(result.message || 'Operacja nie powiodła się.');
  }
  return result;
}
function armIdle(expires) {
  if (!state) return;
  state.idleExpiresAt = expires; clearTimeout(idleTimer);
  idleTimer = setTimeout(async () => {
    try { await api('/logout', 'POST'); } catch {}
    state = null; modal.close(); renderLogin('Sesja wygasła z powodu bezczynności.');
  }, Math.max(0, expires - Date.now()) + 100);
}
async function activity() {
  if (!state || Date.now() - lastActivity < 15000) return;
  lastActivity = Date.now();
  try { const r = await api('/activity', 'POST'); armIdle(r.idleExpiresAt); } catch {}
}
for (const event of ['pointerdown','keydown','scroll']) document.addEventListener(event, activity, { passive: true });
function bindForm(id, handler) {
  $(id).addEventListener('submit', async e => {
    e.preventDefault(); const form = e.currentTarget, button = $('[type=submit]', form); setError(form, ''); button.disabled = true;
    try { await handler(Object.fromEntries(new FormData(form)), form); } catch (error) { setError(form, error.message); } finally { button.disabled = false; }
  });
}
function renderLogin(message = '') {
  app.innerHTML = `<div class="login-page"><aside class="login-art">${brand()}<div class="orbit"></div><div class="login-copy"><div class="eyebrow">Twoja przestrzeń do pracy</div><h1>Dobry zespół.<br>Wspólne miejsce.</h1><p>Notatki, ludzie i bezpieczny dostęp.<br>Wszystko, czego potrzebujesz, w jednym miejscu.</p></div><div class="login-footer">${icon('shield')} Dostęp tylko dla członków zespołu</div></aside><main class="login-main"><div class="login-box">${brand('mobile-brand')}<div class="login-icon">${icon('lock')}</div><h1>Dobrze Cię widzieć</h1><p class="muted">Zaloguj się do swojej przestrzeni zespołu.</p><form id="login-form"><div class="error" ${message ? '' : 'hidden'}>${esc(message)}</div><div class="field"><label for="login">Login</label><input id="login" name="login" autocomplete="username" required maxlength="40" placeholder="Twój login" autofocus></div>${passwordField('password','Hasło','current-password')}<button class="btn full" type="submit">Zaloguj się ${icon('arrow')}</button></form><div class="login-bottom">Pierwsze logowanie lub problem z dostępem?<br><strong>Skontaktuj się z administratorem zespołu.</strong></div></div></main></div>`;
  bindForm('#login-form', async data => { state = await api('/login','POST',data); armIdle(state.idleExpiresAt); view = state.user.role === 'Administrator' ? 'users' : 'notes'; if (state.mustChange) renderChange(); else await renderShell(); });
}
function passwordForm() { return `<form id="password-form"><div class="error" hidden></div>${passwordField('oldPassword','Obecne hasło','current-password')}${passwordField('newPassword','Nowe hasło')}${passwordField('confirmation','Powtórz nowe hasło')}<p class="hint">Minimum ${state.settings.minLength} znaków. Hasło musi różnić się od wszystkich poprzednich.${state.settings.policyEnabled ? ' Nie może zawierać słów ze słownika organizacji.' : ''}</p><button type="submit" class="btn full">Zmień hasło ${icon('arrow')}</button></form>`; }
function bindPassword() { bindForm('#password-form', async data => { const r = await api('/password','POST',data); state = null; clearTimeout(idleTimer); renderLogin(); toast(r.message); }); }
function renderChange() {
  app.innerHTML = `<main class="change-page"><div class="change-box">${brand()}<div class="eyebrow">Bezpieczeństwo konta</div><h1>Ustaw nowe hasło</h1><p>Witaj, ${esc(state.user.name)}. Przed przejściem dalej zmień ${state.user.mustChange ? 'hasło jednorazowe' : 'hasło, którego ważność upłynęła'}.</p>${passwordForm()}<button class="btn text full" data-action="logout">Wyloguj się</button></div></main>`; bindPassword();
}
const titles = { users: 'Użytkownicy', settings: 'Polityka haseł', notes: 'Notatki zespołu', account: 'Moje konto' };
async function renderShell() {
  const isAdmin = state.user.role === 'Administrator';
  if (!isAdmin && ['users','settings'].includes(view)) view = 'notes';
  app.innerHTML = `<div class="shell"><aside class="sidebar">${brand()}<div class="nav-label">Przestrzeń zespołu</div><nav class="nav" aria-label="Menu główne">${[['notes','notes'],...(isAdmin ? [['users','users'],['settings','shield']] : []),['account','user']].map(([id, symbol]) => `<button data-view="${id}" class="${id === view ? 'active' : ''}" ${id === view ? 'aria-current="page"' : ''}>${icon(symbol)}${titles[id]}</button>`).join('')}</nav><div class="sidebar-foot"><strong>Portal zespołu</strong><br>Moduł 1 · Wariant 10</div></aside><header class="topbar"><div class="breadcrumb"><span>Przestrzeń zespołu</span><span>/</span><strong>${titles[view]}</strong></div><div class="user-menu"><div class="avatar">${esc(initials(state.user.name))}</div><div class="user-info"><strong>${esc(state.user.name)}</strong><span>${esc(state.user.role)}</span></div><div class="logout"><button class="icon-btn" data-action="logout" title="Wyloguj się" aria-label="Wyloguj się">${icon('logout')}</button></div></div></header><main class="main" id="main"><p class="muted">Wczytywanie…</p></main></div>`;
  try {
    if (view === 'users') await renderUsers();
    if (view === 'settings') renderSettings();
    if (view === 'notes') await renderNotes();
    if (view === 'account') renderAccount();
  } catch(e) { if ($('#main')) $('#main').innerHTML = `<div class="error">${esc(e.message)}</div>`; }
}
const footer = () => `<footer class="page-footer"><span>Portal zespołu · Wariant 10</span><span class="secure-label">${icon('shield')} Automatyczne wylogowanie po ${state.settings.idleMinutes} min bezczynności</span></footer>`;
const heading = (title, subtitle, button = '') => `<div class="page-heading"><div><div class="eyebrow">${view === 'users' || view === 'settings' ? 'Administracja' : 'Przestrzeń zespołu'}</div><h1>${title}</h1><p>${subtitle}</p></div>${button}</div>`;
async function renderUsers() {
  users = await api('/admin/users');
  $('#main').innerHTML = `${heading('Użytkownicy','Zarządzaj kontami i dostępem do przestrzeni zespołu.',`<button class="btn" data-action="add-user">${icon('plus')}Dodaj użytkownika</button>`)}<div class="stats"><div class="stat"><div><p>Wszyscy użytkownicy</p><strong>${users.length}</strong></div><span class="stat-icon">${icon('users')}</span></div><div class="stat"><div><p>Aktywne konta</p><strong>${users.filter(u => !u.blocked).length}</strong></div><span class="stat-icon green">${icon('check')}</span></div><div class="stat"><div><p>Zablokowane konta</p><strong>${users.filter(u => u.blocked).length}</strong></div><span class="stat-icon orange">${icon('lock')}</span></div></div><section class="panel"><div class="panel-head"><h2>Członkowie zespołu <span>${users.length}</span></h2><div class="filters"><div class="search">${icon('search')}<input type="search" id="search-users" placeholder="Szukaj użytkownika…" aria-label="Szukaj użytkownika"></div><select id="filter-role" aria-label="Filtruj według roli"><option value="">Wszystkie role</option>${roles.map(r => `<option>${r}</option>`).join('')}</select></div></div><div class="table-scroll"><table><thead><tr><th>Użytkownik</th><th>Rola</th><th>Status</th><th>Hasło</th><th>Akcje</th></tr></thead><tbody id="user-rows"></tbody></table></div><div class="table-footer"><span id="user-count"></span><span>Uprawnienia według przypisanej roli</span></div></section>${footer()}`;
  drawUsers(); $('#search-users').addEventListener('input', drawUsers); $('#filter-role').addEventListener('change', drawUsers);
}
function drawUsers() {
  const search = $('#search-users').value.toLocaleLowerCase('pl'), role = $('#filter-role').value;
  const filtered = users.filter(u => (!role || u.role === role) && `${u.name} ${u.login}`.toLocaleLowerCase('pl').includes(search));
  $('#user-rows').innerHTML = filtered.map(u => `<tr><td><div class="person"><span class="avatar">${esc(initials(u.name))}</span><div><strong>${esc(u.name)}</strong><small>${esc(u.login)}</small></div></div></td><td><span class="role ${u.role === 'Administrator' ? 'admin' : ''}">${u.role}</span></td><td><span class="status ${u.blocked ? 'blocked' : ''}">${u.blocked ? 'Zablokowane' : 'Aktywne'}</span></td><td><span class="${u.mustChange ? 'status pending' : ''}">${u.mustChange ? (u.otpExpiresAt < Date.now() ? 'Jednorazowe wygasło' : 'Do zmiany') : 'Ustawione'}</span></td><td><div class="actions"><button class="icon-btn" data-action="edit-user" data-id="${u.id}" title="Edytuj konto" aria-label="Edytuj konto ${esc(u.login)}">${icon('edit')}</button>${u.id !== state.user.id ? `<button class="icon-btn" data-action="reset-user" data-id="${u.id}" title="Resetuj hasło" aria-label="Resetuj hasło ${esc(u.login)}">${icon('key')}</button>` : ''}${u.login !== 'ADMIN' && u.id !== state.user.id ? `<button class="icon-btn" data-action="block-user" data-id="${u.id}" title="${u.blocked ? 'Odblokuj' : 'Zablokuj'} konto" aria-label="${u.blocked ? 'Odblokuj' : 'Zablokuj'} ${esc(u.login)}">${icon(u.blocked ? 'check' : 'lock')}</button><button class="icon-btn" data-action="delete-user" data-id="${u.id}" title="Usuń konto" aria-label="Usuń konto ${esc(u.login)}">${icon('trash')}</button>` : ''}</div></td></tr>`).join('') || '<tr><td colspan="5" class="empty">Nie znaleziono użytkowników.</td></tr>';
  $('#user-count').textContent = `Wyświetlono ${filtered.length} z ${users.length} kont`;
}
function openModal(title, body) { modal.innerHTML = `<div class="modal-head"><h2 id="modal-title">${title}</h2><button class="icon-btn" data-action="close-modal" aria-label="Zamknij">${icon('close')}</button></div><div class="modal-body">${body}</div>`; if (!modal.open) modal.showModal(); }
function userModal(u) {
  openModal(u ? 'Edytuj użytkownika' : 'Nowy użytkownik', `<form id="user-form"><div class="error" hidden></div><div class="field"><label for="user-name">Imię i nazwisko</label><input id="user-name" name="name" required minlength="2" maxlength="80" value="${esc(u?.name)}" placeholder="np. Anna Kowalska"></div><div class="field"><label for="user-login">Login</label><input id="user-login" name="login" required minlength="3" maxlength="40" value="${esc(u?.login)}" ${u?.login === 'ADMIN' ? 'readonly' : ''} placeholder="np. anna.kowalska"><span class="hint">3–40 znaków: litery bez polskich znaków, cyfry, _ . -</span></div><div class="field"><label for="user-role">Rola</label><select id="user-role" name="role" ${u?.login === 'ADMIN' ? 'disabled' : ''}>${roles.map(r => `<option ${r === (u?.role || 'Czytelnik') ? 'selected' : ''}>${r}</option>`).join('')}</select></div>${u && u.login !== 'ADMIN' ? `<label class="check"><input type="checkbox" name="blocked" ${u.blocked ? 'checked' : ''}>Konto zablokowane</label>` : ''}${!u ? '<p class="hint">Hasło jednorazowe zostanie wygenerowane automatycznie i będzie ważne przez 12 godzin.</p>' : ''}<div class="modal-actions"><button type="button" class="btn secondary" data-action="close-modal">Anuluj</button><button type="submit" class="btn">${u ? 'Zapisz zmiany' : 'Utwórz konto'}</button></div></form>`);
  bindForm('#user-form', async data => {
    if (u) { await api(`/admin/users/${u.id}`,'PUT',{ ...data, role: data.role || u.role, blocked: data.blocked === 'on' }); if (u.id === state.user.id) { state = await api('/session'); await renderShell(); } modal.close(); toast('Zapisano zmiany.'); }
    else { const r = await api('/admin/users','POST',data); credentials(r); }
    await renderUsers();
  });
}
function credentials(r) { openModal('Hasło jednorazowe', `<p>Przekaż dane logowania użytkownikowi. Hasło pokazujemy tylko teraz.</p><div class="credential"><small>LOGIN: ${esc(r.login)}</small><strong>${esc(r.password)}</strong><small>Ważne do ${date(r.expiresAt)}</small></div><div class="notice">Przy pierwszym logowaniu użytkownik musi ustawić własne hasło.</div><div class="modal-actions"><button class="btn secondary" id="copy-password">Kopiuj hasło</button><button class="btn" data-action="close-modal">Gotowe</button></div>`); $('#copy-password').onclick = async () => { try { await navigator.clipboard.writeText(r.password); toast('Skopiowano hasło.'); } catch { toast('Zaznacz hasło i skopiuj je ręcznie.', true); } }; }
function confirmModal(title, message, action, label = 'Potwierdź') { openModal(title, `<form id="confirm-form"><div class="error" hidden></div><p>${message}</p><div class="modal-actions"><button type="button" class="btn secondary" data-action="close-modal">Anuluj</button><button type="submit" class="btn danger">${label}</button></div></form>`); bindForm('#confirm-form', action); }
function renderSettings() {
  const s = state.settings;
  $('#main').innerHTML = `${heading('Polityka haseł','Ustal zasady dostępu i bezpieczeństwa kont.')}<form id="settings-form"><div class="error" hidden></div><div class="settings-grid"><section class="panel"><div class="panel-body"><div class="section-icon">${icon('shield')}</div><h2>Zasady bezpieczeństwa</h2><p class="muted">Ustawienia obowiązują wszystkich użytkowników.</p><div class="field"><label for="minLength">Minimalna długość hasła</label><input type="number" id="minLength" name="minLength" min="14" max="128" value="${s.minLength}" required><span class="hint">Wariant 10: domyślnie 14 znaków.</span></div><div class="row"><div class="field"><label for="passwordDays">Ważność hasła (dni)</label><input type="number" id="passwordDays" name="passwordDays" min="0" max="3650" value="${s.passwordDays}" required><span class="hint">0 = bez okresowej zmiany.</span></div><div class="field"><label for="idleMinutes">Bezczynność sesji (min)</label><input type="number" id="idleMinutes" name="idleMinutes" min="1" max="1440" value="${s.idleMinutes}" required><span class="hint">Po tym czasie nastąpi wylogowanie.</span></div></div><hr class="divider"><div class="hint">${icon('key')} Hasło jednorazowe: 3 losowe słowa + 2 cyfry.<br>Ważność: 12 godzin. Pierwsza zmiana jest obowiązkowa.</div></div></section><section class="panel"><div class="panel-body"><div class="section-icon">${icon('notes')}</div><h2>Słownik zakazanych słów</h2><p class="muted">Hasło nie może zawierać żadnego z wpisanych słów.</p><label class="check"><input type="checkbox" name="policyEnabled" ${s.policyEnabled ? 'checked' : ''}>Włącz sprawdzanie słownika</label><div class="field"><label for="bannedWords">Zakazane słowa i frazy</label><textarea id="bannedWords" name="bannedWords" rows="9">${esc(s.bannedWords.join('\n'))}</textarea><span class="hint">Każdy wpis w osobnym wierszu. Uwzględnij nazwę firmy lub uczelni, aplikacji, miesiące i pory roku. Wielkość liter i polskie znaki nie wpływają na sprawdzanie.</span></div></div></section></div><div class="modal-actions"><button class="btn" type="submit">${icon('check')}Zapisz ustawienia</button></div></form>${footer()}`;
  bindForm('#settings-form', async d => { state.settings = await api('/admin/settings','PUT',{ minLength: Number(d.minLength), passwordDays: Number(d.passwordDays), idleMinutes: Number(d.idleMinutes), policyEnabled: d.policyEnabled === 'on', bannedWords: d.bannedWords.split('\n').map(w => w.trim()).filter(Boolean) }); const current = await api('/session'); state = current; armIdle(current.idleExpiresAt); toast('Zapisano ustawienia.'); if (state.mustChange) renderChange(); else renderSettings(); });
}
function renderAccount() {
  const u = state.user;
  $('#main').innerHTML = `${heading('Moje konto','Twoje dane i bezpieczeństwo logowania.')}<div class="account-grid"><section class="panel"><div class="panel-body"><div class="profile-top"><div class="avatar">${esc(initials(u.name))}</div><div><h2>${esc(u.name)}</h2><span class="role">${u.role}</span></div></div><div class="detail-row"><span>Login</span><strong>${esc(u.login)}</strong></div><div class="detail-row"><span>Status</span><strong class="status">Aktywne konto</strong></div><div class="detail-row"><span>Ostatnia zmiana hasła</span><strong>${date(u.passwordChangedAt)}</strong></div><div class="detail-row"><span>Ważność hasła</span><strong>${state.settings.passwordDays ? `${state.settings.passwordDays} dni` : 'Bezterminowo'}</strong></div><hr class="divider"><p class="hint">Zmiany danych i przypisanej roli dokonuje administrator zespołu.</p></div></section><section class="panel"><div class="panel-body"><h2>Zmiana hasła</h2><p class="muted">Po zmianie hasła zalogujesz się ponownie.</p>${passwordForm()}</div></section></div>${footer()}`; bindPassword();
}
async function renderNotes() {
  notes = await api('/notes');
  $('#main').innerHTML = `${heading('Notatki zespołu','Wspólne informacje i materiały robocze.',state.user.role !== 'Czytelnik' ? `<button class="btn" data-action="add-note">${icon('plus')}Nowa notatka</button>` : '')}<div class="notes">${notes.map(n => `<article class="note"><div class="note-top"><span class="tag ${n.published ? '' : 'draft'}">${n.published ? 'Opublikowana' : 'Szkic'}</span><span class="muted">${date(n.updated_at)}</span></div><h2>${esc(n.title)}</h2><p>${esc(n.body)}</p><div class="note-bottom"><span>${esc(n.author || 'Usunięte konto')}</span><div class="actions">${n.canEdit ? `<button class="icon-btn" data-action="edit-note" data-id="${n.id}" title="Edytuj notatkę" aria-label="Edytuj notatkę">${icon('edit')}</button><button class="icon-btn" data-action="delete-note" data-id="${n.id}" title="Usuń notatkę" aria-label="Usuń notatkę">${icon('trash')}</button>` : ''}${n.canPublish ? `<button class="btn secondary small" data-action="publish-note" data-id="${n.id}">${n.published ? 'Cofnij publikację' : 'Opublikuj'}</button>` : ''}</div></div></article>`).join('') || `<div class="panel empty">${icon('notes')}Nie ma jeszcze notatek do wyświetlenia.</div>`}</div>${footer()}`;
}
function noteModal(n) {
  openModal(n ? 'Edytuj notatkę' : 'Nowa notatka', `<form id="note-form"><div class="error" hidden></div><div class="field"><label for="note-title">Tytuł</label><input id="note-title" name="title" maxlength="120" required value="${esc(n?.title)}" placeholder="O czym jest ta notatka?"></div><div class="field"><label for="note-body">Treść</label><textarea id="note-body" name="body" rows="7" maxlength="5000" required placeholder="Zapisz informacje dla zespołu…">${esc(n?.body)}</textarea></div><p class="hint">Notatka zostanie zapisana jako szkic. Publikację zatwierdza kierownik lub administrator.</p><div class="modal-actions"><button type="button" class="btn secondary" data-action="close-modal">Anuluj</button><button class="btn" type="submit">Zapisz szkic</button></div></form>`);
  bindForm('#note-form', async data => { await api(n ? `/notes/${n.id}` : '/notes', n ? 'PUT' : 'POST', data); modal.close(); toast('Zapisano notatkę.'); await renderNotes(); });
}
document.addEventListener('click', async e => {
  const show = e.target.closest('[data-show]');
  if (show) { const input = document.getElementById(show.dataset.show); input.type = input.type === 'password' ? 'text' : 'password'; show.setAttribute('aria-label', input.type === 'password' ? 'Pokaż hasło' : 'Ukryj hasło'); return; }
  const nav = e.target.closest('[data-view]');
  if (nav) { view = nav.dataset.view; await renderShell(); return; }
  const button = e.target.closest('[data-action]'); if (!button) return;
  const { action, id } = button.dataset, u = users.find(x => x.id === Number(id)), n = notes.find(x => x.id === Number(id));
  try {
    if (action === 'close-modal') modal.close();
    if (action === 'logout') { await api('/logout','POST'); state = null; clearTimeout(idleTimer); renderLogin(); toast('Wylogowano bezpiecznie.'); }
    if (action === 'add-user') userModal();
    if (action === 'edit-user') userModal(u);
    if (action === 'block-user') { await api(`/admin/users/${id}`,'PUT',{ ...u, blocked: !u.blocked }); toast(u.blocked ? 'Odblokowano konto.' : 'Zablokowano konto i zakończono jego sesje.'); await renderUsers(); }
    if (action === 'delete-user') confirmModal('Usuń użytkownika', `Usunąć konto <strong>${esc(u.login)}</strong>? Tej operacji nie można cofnąć.`, async () => { await api(`/admin/users/${id}`,'DELETE'); modal.close(); toast('Usunięto konto.'); await renderUsers(); }, 'Usuń konto');
    if (action === 'reset-user') confirmModal('Reset hasła', `Wygenerować nowe hasło jednorazowe dla <strong>${esc(u.login)}</strong>? Obecne hasło i sesje przestaną działać.`, async () => { credentials(await api(`/admin/users/${id}/reset`,'POST')); await renderUsers(); }, 'Resetuj hasło');
    if (action === 'add-note') noteModal();
    if (action === 'edit-note') noteModal(n);
    if (action === 'delete-note') confirmModal('Usuń notatkę', `Usunąć notatkę <strong>${esc(n.title)}</strong>?`, async () => { await api(`/notes/${id}`,'DELETE'); modal.close(); await renderNotes(); }, 'Usuń notatkę');
    if (action === 'publish-note') { await api(`/notes/${id}/publish`,'POST',{ published: !n.published }); await renderNotes(); toast(n.published ? 'Cofnięto publikację.' : 'Opublikowano notatkę.'); }
  } catch(error) { toast(error.message, true); }
});
async function init() {
  try { state = await api('/session'); armIdle(state.idleExpiresAt); view = state.user.role === 'Administrator' ? 'users' : 'notes'; if (state.mustChange) renderChange(); else await renderShell(); }
  catch { renderLogin(); }
}
init();
