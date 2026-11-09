async function runBot() {
  console.log("=== ROZPOCZĘCIE SYMULACJI ATAKU BOTA NA PORTAL ZESPOŁU ===\n");

  const targetUrl = 'http://127.0.0.1:3100/api/login';

  // TEST 1: Honeytoken (Ukryte pole)
  console.log("-> TEST 1: Bot skanuje stronę i wypełnia ukryte pole (Honeytoken)");
  try {
    const res1 = await fetch(targetUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ login: 'bot1', password: '123', website: 'http://spam-link.com' })
    });
    const data1 = await res1.json();
    console.log(`[WYNIK]: Status HTTP ${res1.status} - ${data1.message}\n`);
  } catch (e) { console.log("Błąd połączenia. Upewnij się, że serwer działa."); return; }

  // TEST 2: Brak weryfikacji CAPTCHA
  console.log("-> TEST 2: Bot próbuje wysłać formularz ignorując system CAPTCHA");
  const res2 = await fetch(targetUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ login: 'bot2', password: '123' }) // Brak pola turnstile
  });
  const data2 = await res2.json();
  console.log(`[WYNIK]: Status HTTP ${res2.status} - ${data2.message}\n`);

  // TEST 3: Atak typu spam / Brute Force (weryfikacja limitu IP na ocenę BDB)
  console.log("-> TEST 3: Agresywny atak słownikowy (wysyłanie zapytań w pętli)");
  for (let i = 1; i <= 12; i++) {
    const res3 = await fetch(targetUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ login: `test_user${i}`, password: 'password123' })
    });
    const data3 = await res3.json();
    
    if (res3.status === 429) {
      console.log(`[WYNIK Próba ${i}]: Status HTTP 429 - ZABEZPIECZENIE ZADZIAŁAŁO: ${data3.message}\n`);
      break; 
    } else {
      console.log(`   Próba ${i}: Odrzucono (brak weryfikacji)`);
    }
  }
  
  console.log("=== SYMULACJA ZAKOŃCZONA ===");
}

runBot();