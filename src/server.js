import path from 'node:path';
import { createApp } from './app.js';
import { DATA_DIR } from './config/paths.js';

const { app, initialAdminPassword } = await createApp();
const port = Number(process.env.PORT || 3100);
app.listen(port, '127.0.0.1', () => {
  console.log(`\nPortal zespołu: http://127.0.0.1:${port}\nKonta początkowe: ${path.join(DATA_DIR, 'pierwsze-logowanie.txt')}`);
  if (initialAdminPassword) {
    console.log(`\n--- KONTO ADMINISTRATORA ---\nLogin: ADMIN\nHasło jednorazowe: ${initialAdminPassword}\nSkopiuj hasło powyżej. Wygasa 12 godzin od wygenerowania.\nPrzy pierwszym logowaniu ustaw własne hasło.`);
  } else {
    console.log('\nLogin administratora: ADMIN\nUżyj ustawionego hasła. Jeśli hasło startowe wygasło lub zostało utracone: npm run reset-admin');
  }
  console.log('\nZatrzymanie: Ctrl+C\n');
}).on('error', error => {
  console.error(error.code === 'EADDRINUSE' ? `Port ${port} jest już zajęty. Jeśli portal już działa, otwórz http://127.0.0.1:${port}.` : error.message);
  process.exit(1);
});
