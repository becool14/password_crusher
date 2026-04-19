# Projekt: Ochrona danych w aplikacjach

Temat: **Heszowanie hasel i odpornosc na ataki offline**.

## Struktura

- `app/main.py` - testowa aplikacja Flask (register/login)
- `app/password_utils.py` - haszowanie i weryfikacja (AlgorithmSpec, registry)
- `config.py` - konfiguracja aplikacji (DB_PATH, SUPPORTED_ALGORITHMS, itp.)
- `data/wordlist.txt` - lista hasel do ataku slownikowego (edytowalna)
- `scripts/generate_users.py` - tworzenie danych testowych
- `scripts/export_hashes.py` - eksport hashy do `hashes/`
- `scripts/run_attacks.py` - ataki slownikowy i brute-force
- `scripts/generate_charts.py` - wykresy do raportu

## Obslugiwane algorytmy

| Algorytm | Typ | Salt | Uwagi |
|---|---|---|---|
| MD5 | slaby | nie | tylko referencyjny |
| SHA-1 | slaby | nie | tylko referencyjny |
| SHA-256 | slaby | nie | tylko referencyjny |
| PBKDF2-SHA256 | nowoczesny | tak | 260 000 iteracji |
| scrypt | nowoczesny | tak | n=16384, r=8, p=1 |
| bcrypt | nowoczesny | tak | cost=12 |
| Argon2id | nowoczesny | tak | time=3, mem=64MB, par=2 |

## Szybki start

1. Instalacja zaleznosci:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

2. (Opcjonalnie) ustaw pepper:

```bash
export PASSWORD_PEPPER="tajny_klucz_aplikacji"
```

3. Przygotowanie danych:

```bash
python scripts/generate_users.py
python scripts/export_hashes.py
```

4. Ataki i wyniki:

```bash
# domyslnie 4 workers
python scripts/run_attacks.py

# z wiekszą liczba workersow (zalecane: liczba fizycznych rdzeni CPU)
python scripts/run_attacks.py --workers 6
```

5. Wykresy:

```bash
python scripts/generate_charts.py
```

6. Uruchomienie aplikacji:

```bash
python app/main.py
```

## Atak slownikowy — mutacje

Skrypt `run_attacks.py` rozszerza liste slow z `data/wordlist.txt` o automatyczne mutacje:
- wielkosc liter: lowercase, uppercase, capitalize
- zamiana leet: `a→4`, `e→3`, `i→1`, `o→0`, `s→5`
- dopisanie cyfr: 10, 12, 123, 2024, ...
- dopisanie symboli: `!`, `@`, `#`, `$`, ...
- kombinacje: `Word123!`

Przy domyslnej liscie 35 slow generuje ~22 000 unikalnych kandydatow.  
Aby rozszerzyc atak, wystarczy dodac hasla do `data/wordlist.txt`.

## Uwaga etyczna

Wszystkie testy nalezy wykonywac wylacznie na danych testowych i za zgoda wlasciciela systemu.  
Projekt ma charakter edukacyjny i dotyczy bezpiecznego projektowania aplikacji.
