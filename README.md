# Portal zespołu — wariant 10

## Uruchomienie

1. Zainstaluj **Node.js 24 lub nowszy** (https://nodejs.org), jeśli nie masz go na komputerze.
2. Kliknij **Uruchom.bat**. Przy pierwszym uruchomieniu pobierane są biblioteki (wymaga internetu).
3. Otwórz **http://127.0.0.1:3100**. Zostaw okno serwera otwarte.
4. Terminal wyświetla login **ADMIN** i hasło startowe do skopiowania, również przy ponownym uruchomieniu, dopóki hasło pozostaje ważne i niezmienione. Dane kont testowych są w **data/pierwsze-logowanie.txt** (plik zawiera też kopię hasła startowego ADMIN). Po zmianie hasła, resecie, wygaśnięciu lub usunięciu tego pliku stare hasło nie jest wyświetlane. Uruchomienie serwera nie zmienia haseł.
5. Przy pierwszym logowaniu wpisz hasło jednorazowe jako obecne i ustaw własne hasło (minimum 14 znaków).

Alternatywnie: `npm.cmd ci`, a następnie `npm.cmd start`. Testy: `npm.cmd test`.

Hasła początkowe są ważne przez 12 godzin od utworzenia bazy. Plik z nimi służy wyłącznie do pierwszego logowania — po ustawieniu własnych haseł usuń go. SQLite przechowuje wyłącznie hashe Argon2id z solą. **Nie otwieraj index.html bezpośrednio**: aplikacja wymaga działającego serwera Node.js.

Jeśli hasło ADMIN wygasło albo zostało zapomniane: w folderze projektu uruchom `npm.cmd run reset-admin`. Polecenie wyświetla nowe hasło jednorazowe i unieważnia sesje administratora. Dostęp do folderu i bazy jest dostępem administracyjnym. Hasła pozostałych kont resetuje administrator w panelu.

## Konta i zakres

Stałe konto ADMIN oraz **7 użytkowników testowych**: anna (Kierownik), marek i ewa (Redaktor), piotr i ola (Pracownik), jan i zofia (Czytelnik).

Wariant 10: minimum 14 znaków, edytowalny słownik zakazanych fragmentów hasła, przełącznik sprawdzania słownika, hasło jednorazowe 3 słowa + 2 cyfry ważne 12 godzin. Porównanie słownika ignoruje wielkość liter i polskie znaki. Historia obejmuje wszystkie poprzednie hasła, również hasła sprzed resetu. Prosta lista najpopularniejszych haseł jest blokowana niezależnie od słownika organizacji.

Administrator zarządza użytkownikami (dodawanie, edycja, blokowanie, usuwanie, reset hasła), ważnością hasła oraz czasem bezczynności. Domyślnie hasło jest bezterminowe, sesja wygasa po 15 minutach bezczynności. Minimalny ustawiany czas sesji: 1 minuta. Stałego konta ADMIN nie można usunąć, zablokować, zmienić mu loginu ani odebrać roli.

Notatki służą do sprawdzania uprawnień ról:

| Operacja | Czytelnik | Pracownik | Redaktor | Kierownik | Administrator |
|---|---|---|---|---|---|
| Odczyt opublikowanych notatek | Tak | Tak | Tak | Tak | Tak |
| Tworzenie szkicu | Nie | Tak | Tak | Tak | Tak |
| Odczyt, edycja, usuwanie szkiców | Nie | Własne | Wszystkie | Wszystkie | Wszystkie |
| Publikacja / cofanie publikacji | Nie | Nie | Nie | Tak | Tak |
| Zarządzanie kontami i polityką | Nie | Nie | Nie | Nie | Tak |
| Zmiana własnego hasła | Tak | Tak | Tak | Tak | Tak |

Opublikowaną notatkę trzeba przenieść do szkiców przed edycją lub usunięciem. Autoryzacja jest sprawdzana na serwerze; niedozwolone działania zwracają HTTP 403.

## Struktura projektu

```text
portal-zespolu/
├── src/
│   ├── server.js              # uruchomienie serwera HTTP
│   ├── app.js                 # składanie aplikacji Express
│   ├── config/                # ścieżki i dostępne role
│   ├── database/              # SQLite, schemat SQL, konta testowe, magazyn sesji
│   ├── middleware/            # uwierzytelnianie i kontrola uprawnień
│   ├── routes/                # API logowania, administracji i notatek
│   ├── services/              # hashowanie i generowanie haseł
│   └── utils/                 # wspólne funkcje pomocnicze
├── public/
│   ├── index.html
│   ├── css/style.css
│   └── js/app.js
├── scripts/
│   ├── reset-admin.js         # lokalne odzyskanie dostępu ADMIN
│   └── package-project.ps1    # tworzenie archiwum projektu
├── test/app.test.js           # testy integracyjne API
├── data/                     # dane lokalne; tworzone przy uruchomieniu
├── dist/                     # wynik pakowania; poza repozytorium
├── .editorconfig
├── .gitignore
├── package.json
├── package-lock.json
├── Uruchom.bat
└── README.md
```

`src/app.js` udostępnia fabrykę aplikacji, dzięki czemu testy uruchamiają osobną instancję z tymczasową bazą. `src/server.js` odpowiada tylko za uruchomienie serwera. Ścieżki do `public` i `data` są wyznaczane względem katalogu projektu, niezależnie od miejsca uruchomienia polecenia.

Baza znajduje się w `data/portal.sqlite`, a losowy sekret podpisu sesji w `data/session-secret`. Pliki interfejsu nie korzystają z zewnętrznych fontów ani CDN.

Projekt działa lokalnie na `127.0.0.1`. Dane sesji są po stronie serwera; cookie ma HttpOnly i SameSite=Strict. Żądania zmieniające stan wymagają tokenu CSRF, poza logowaniem chronionym weryfikacją Origin. Logowanie ma limit 20 prób na minutę na adres IP. Dla HTTPS ustaw `HTTPS=1`, aby wymusić Secure na cookie.

## Pakowanie do ZIP-a

W terminalu w katalogu projektu uruchom:

```powershell
npm run pack
```

Gotowy plik: **dist/portal-zespolu-wariant-10.zip**. Polecenie działa na Windows i przy kolejnym wywołaniu aktualizuje archiwum. Dołącza kod, testy, skrypty, konfigurację i instrukcję. Pomija `node_modules`, `.git`, `tmp`, lokalną bazę, hasła i sekret sesji. Jest to paczka źródłowa, a nie kopia zapasowa bieżących kont.

Po rozpakowaniu do nowego folderu uruchom `Uruchom.bat`. Aplikacja pobierze biblioteki i utworzy bazę z nowymi hasłami jednorazowymi. Na obecnym komputerze dotychczasowa baza i konta pozostają zachowane. Nie dodano TOTP ani sprawozdania.
