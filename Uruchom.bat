@echo off
chcp 65001 >nul
cd /d "%~dp0"
where node >nul 2>&1
if errorlevel 1 (
  echo Zainstaluj Node.js w wersji 24 lub nowszej: https://nodejs.org
  pause
  exit /b 1
)
node -e "if(Number(process.versions.node.split('.')[0])<24)process.exit(1)"
if errorlevel 1 (
  echo Wymagany jest Node.js 24 lub nowszy.
  pause
  exit /b 1
)
if not exist node_modules\express (
  call npm ci --no-audit --no-fund
  if errorlevel 1 (
    echo Nie udalo sie pobrac bibliotek. Sprawdz polaczenie z internetem.
    pause
    exit /b 1
  )
)
echo.
echo Otworz w przegladarce: http://127.0.0.1:3100
echo Hasla poczatkowe znajdziesz w data\pierwsze-logowanie.txt
echo Po pojawieniu sie adresu ponizej aplikacja jest gotowa.
echo Zamkniecie tego okna zatrzyma serwer.
echo.
call npm start
pause
