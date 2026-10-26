import argon2 from 'argon2';
import { randomInt } from 'node:crypto';

const WORDS = ['bursztyn', 'most', 'kamyk', 'sosna', 'obraz', 'szlak', 'pociag', 'chmura', 'koral', 'zamek', 'pioro', 'zegar', 'rzeka', 'las', 'latarnia', 'kotwica', 'zagiel', 'sokol', 'kompas', 'perla', 'atlas', 'bukiet', 'klucz', 'fotel', 'balon', 'rower', 'wulkan', 'szafir', 'tunel', 'harfa', 'globus', 'notes', 'lampa', 'bilet', 'wstega', 'rakieta', 'lis', 'koszyk', 'fala', 'jodla', 'kaktus', 'orzel', 'pagorek', 'dzwon', 'ogrod', 'zameczek', 'kreda', 'mysz', 'taras', 'gruszka', 'jablko', 'czapla', 'wrona', 'sarna', 'plecak', 'kubek', 'wazon', 'szyszka', 'strumien', 'obrus', 'dywan', 'wioslo', 'skala', 'peron'];
export const hash = password => argon2.hash(password, { type: argon2.argon2id, memoryCost: 19456, timeCost: 2, parallelism: 1 });
export const normalize = text => text.toLocaleLowerCase('pl').normalize('NFD').replace(/\p{Diacritic}/gu, '').replace(/ł/g, 'l');
export const otp = () => `${WORDS[randomInt(WORDS.length)]}-${WORDS[randomInt(WORDS.length)]}-${WORDS[randomInt(WORDS.length)]}-${String(randomInt(100)).padStart(2, '0')}`;
