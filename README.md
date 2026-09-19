# zapret-cpp

Клон zapret на C++: перехват исходящего TCP через WinDivert и обход DPI
десинхронизацией TLS ClientHello. Реализованы техники из
[Flowseal/zapret-discord-youtube](https://github.com/Flowseal/zapret-discord-youtube):
`split`, `disorder`, `multidisorder`, `fake`, `fake-multidisorder`, fooling `badseq`,
модификаторы фейка и повторы.

## Как это работает

1. WinDivert перехватывает исходящие TCP-пакеты (443/80/8443).
2. Парсер TLS достаёт из ClientHello позицию и значение `server_name` (SNI).
3. Хост сверяется со списком сервисов (Google, YouTube, Discord, Telegram и др.).
4. Стратегия десинхронизирует ClientHello так, чтобы DPI не собрал SNI целиком:
   - **split** — разрезать на два TCP-сегмента;
   - **disorder** — те же два сегмента, но второй уходит первым;
   - **multidisorder** — разрезать на 2–8 сегментов и отправить в обратном порядке;
   - **fake** — фейковый ClientHello с низким TTL (умрёт в пути, DPI «съест» подмену);
   - **fake-multidisorder** — комбо: фейк + multidisorder (основной рабочий режим);
   - **fake-auto** — фейк с автоподбором decoy-SNI;
   - fooling `badseq` — битый TCP seq на трюк-сегменте сбивает stateful DPI.

## Сервисы (whitelist)

По умолчанию обход применяется **только** к доменам из списка (`--list` покажет всё),
остальной трафик идёт как есть. Список доменов взят из `lists/list-general.txt`
флоусиловского репо (`googlevideo`, `gvt1-8.com`, `discordcdn`, `7tv`, `betterttv` и т.д.).

```
google  google-play  youtube  discord  discord-cdn  instagram  facebook
twitter  telegram  whatsapp  reddit  wikipedia  github  openai  spotify
netflix  twitch  roblox  cloudflare  cloudfront  discord-addons  discord-live
```

У каждого сервиса своя стратегия, число повторов и fooling.

## Зависимости

- MinGW-w64 / MSYS2 (`g++`, `cmake`, `ninja`) — уже стоят в `D:\msys2\ucrt64`.
- WinDivert SDK → положить в `third_party/windivert/`:
  ```
  third_party/windivert/
    include/windivert.h
    x64/WinDivert.dll
    x64/WinDivert.lib
    x64/WinDivert64.sys
  ```
  Скачать: https://github.com/basil00/WinDivert/releases (не коммитить SDK в git).
  Проверено на **WinDivert 2.2.2-A**.

> **Важно (GCC 16 / MinGW):** в `main.cpp` C++-заголовки (`<string>`, `<vector>`)
> обязаны идти **до** `<windows.h>` и `<windivert.h>`. Иначе `windows.h`
> подменяет `vsnprintf` и libstdc++ разваливается сотнями ошибок в системных
> заголовках. Это особенность конкретной сборки MSYS2, а не ошибка кода.

## Сборка

```sh
cmake -S . -B build -G Ninja
cmake --build build
```

Тесты чистой логики (без драйвера):

```sh
cmake --build build --target logic_test
./build/logic_test.exe
```

Проверка без WinDivert:

```sh
g++ -std=c++17 -Isrc tests/logic_test.cpp src/csum.cpp src/tls.cpp src/services.cpp -o build/logic_test.exe
```

## Запуск

Нужны **права администратора** (WinDivert грузит драйвер). `WinDivert.dll` и
`WinDivert64.sys` должны лежать рядом с exe (скопируй из `third_party/windivert/x64/`).

```sh
./zapret-cpp.exe                          # авто-стратегии по сервисам, только whitelist
./zapret-cpp.exe --all                    # обходить любые TLS-хосты
./zapret-cpp.exe --strategy=fake-auto     # одна стратегия на всех
./zapret-cpp.exe --list                   # показать список сервисов и выйти
./zapret-cpp.exe --repeats=11 --badseq    # усилить: 11 повторов + badseq
```

Флаги:

| флаг | смысл | default |
|------|-------|---------|
| `--strategy` | `split` \| `disorder` \| `multidisorder` \| `fake` \| `fake-multidisorder` \| `fake-auto` | `fake-multidisorder` |
| `--split` | смещение разреза, `-1` = авто (середина SNI) | `-1` |
| `--ttl` | TTL фейкового пакета | `4` |
| `--fake-sni` | подменный хост для fake-стратегий | `www.google.com` |
| `--repeats` | отправить десинк-пакеты N раз | `1` |
| `--segs` | число сегментов multidisorder (2..8) | `4` |
| `--badseq` | битый seq на трюк-сегменте (fooling) | off |
| `--fake-rnd` | рандомить байты фейкового TLS | off |
| `--all` | обходить все хосты, не только whitelist | off |
| `--no-auto` | одна `--strategy` на всех, игнор per-service | off |
| `--list` | вывести список сервисов | — |
| `--filter` | свой WinDivert-фильтр | `outbound and tcp and (tcp.DstPort == 443 or tcp.DstPort == 80)` |

Останов — `Ctrl+C`.

## Структура

```
src/csum.*      контрольные суммы (RFC 1071)
src/tls.*       парсер TLS ClientHello → SNI (offset + строка)
src/packet.*    разбор/пересборка IP/TCP пакета
src/desync.*    стратегии десинхронизации
src/services.*  список сервисов и per-service стратегии
src/main.cpp    WinDivert-цикл + CLI
tests/          тесты логики (checksum, SNI, матчинг сервисов)
```

## Ограничения / куда копать дальше

- UDP/QUIC (HTTP/3) не трогается — в zapret это делается через
  `--dpi-desync=fake --dpi-desync-fake-quic=...`. Следующий большой шаг.
- Нет обхода по IP-адресу (`--ipset`), только по SNI. Для игр (Discord voice, STUN)
  нужен IP-фильтр.
- IPv6 парсится, но не тестировался на живом трафике.
- Идеи: авто-подбор рабочей стратегии (перебор + проверка доступности),
  UDP/QUIC fake, Game Filter для портов >1023, чтение доменов из `list-general-user.txt`.
