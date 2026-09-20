# zapret-cpp

Универсальный обход DPI на C++ через WinDivert. Один exe, работает из коробки:
перехватывает **TCP+TLS, HTTP и QUIC (HTTP/3)** и десинхронизирует трафик так,
чтобы DPI не собрал домен/SNI. Знакомые сервисы получают подобранную стратегию,
всё остальное (включая любые нейросети) — универсальный fallback.

Основано на техниках из
[Flowseal/zapret-discord-youtube](https://github.com/Flowseal/zapret-discord-youtube).

## Что обходит

- **TLS (HTTPS)** — Google, YouTube, Discord (+CDN, голос), Telegram, Instagram,
  Facebook, Twitter/X, Reddit, GitHub и др.
- **Все нейросети/AI** — OpenAI/ChatGPT, Anthropic/Claude, Gemini/DeepMind,
  Copilot/Bing, Groq, Perplexity, xAI/Grok, Mistral, HuggingFace, DeepSeek,
  Midjourney, ElevenLabs, Character.AI, Poe.
- **QUIC (HTTP/3)** — UDP/443 initial-пакеты (fake + real).
- **Plain HTTP** — порт 80.
- Любой прочий хост — универсальным fallback'ом (`--all`, включён по умолчанию).

## Стратегии

- **split** — разрезать ClientHello на два TCP-сегмента;
- **disorder** — те же сегменты, но второй уходит первым;
- **multidisorder** — 2–8 сегментов в обратном порядке;
- **fake** — фейковый пакет с низким TTL (умрёт в пути, DPI «съест» подмену);
- **fake-multidisorder** — комбо (основной режим);
- **fake-auto** — fake с автоподбором decoy-SNI;
- fooling **badseq** — битый TCP seq на трюк-сегменте;
- **QUIC fake** — дубль UDP-пакета с мусором и низким TTL.

## Зависимости

- MinGW-w64 / MSYS2 (`g++`, `cmake`, `ninja`).
- WinDivert SDK в `third_party/windivert/`:
  ```
  third_party/windivert/
    include/windivert.h
    x64/WinDivert.dll
    x64/WinDivert64.sys
  ```
  Скачать: https://github.com/basil00/WinDivert/releases (проверено на 2.2.2-A).
  `.lib` не нужен — API грузится в рантайме через `LoadLibrary`.

> **GCC 16 / MinGW:** в `main.cpp` C++-заголовки (`<string>`, `<vector>`) идут
> **до** `<windows.h>`. Иначе `windows.h` ломает libstdc++ сотнями ошибок.

## Сборка

Единый самодостаточный exe (статическая линковка, без libstdc++/libgcc в
зависимостях; WinDivert грузится через `LoadLibrary`):

```sh
cmake -S . -B build -G Ninja
cmake --build build
```

Тесты логики (без драйвера):

```sh
./build/logic_test.exe
```

## Релиз

Одной командой собирается готовый архив для публикации:

```powershell
pwsh -File scripts/make-release.ps1 -Version v1.0.0
```

Результат в `dist/`: `zapret-cpp.exe` + `WinDivert.dll` + `WinDivert64.sys` +
`README.md`, упакованные в `zapret-cpp-v1.0.0.zip`. Этот архив и выкладывай в
GitHub Releases.

## Запуск

**Только от имени администратора** (WinDivert грузит драйвер). Рядом с exe
обязательны `WinDivert.dll` и `WinDivert64.sys` — из релизного архива они уже
рядом.

> Запускай **двойным кликом** `zapret-cpp.exe` → откроется окно консоли со
> статусом и логом обхода. Окно закроется только по `Ctrl+C` или закрытию.
> Если exe не стартует и окно мигает — почти всегда это (1) отсутствие прав
> администратора или (2) `WinDivert.dll`/`WinDivert64.sys` не лежат рядом с exe.

```sh
# работает из коробки: TLS+HTTP+QUIC, все хосты, авто-стратегии
./zapret-cpp.exe

# только известные сервисы (whitelist)
./zapret-cpp.exe --listed

# усилить под жёсткий DPI
./zapret-cpp.exe --repeats=11 --badseq

# одна стратегия на всех
./zapret-cpp.exe --strategy=fake-auto
```

Флаги:

| флаг | смысл | default |
|------|-------|---------|
| `--strategy` | force strategy (`split`\|`disorder`\|`multidisorder`\|`fake`\|`fake-multidisorder`\|`fake-auto`) | auto per-service |
| `--split` | смещение разреза, `-1` = авто (середина SNI) | `-1` |
| `--ttl` | TTL фейкового пакета | `4` |
| `--fake-sni` | подменный хост для fake | `www.google.com` |
| `--repeats` | повторы **трюк/fake**-пакетов (real-сегменты всегда один раз) | `1` |
| `--segs` | сегментов multidisorder (2..8) | `4` |
| `--badseq` | добавить decoy-пакет с битым seq (для split/disorder/multidisorder) | off |
| `--fake-rnd` | рандомить байты фейка | off |
| `--listed` | только известные сервисы | off (обход всего) |
| `--no-quic` | выключить UDP/QUIC | off |
| `--no-http` | выключить HTTP:80 | off |
| `--no-fake-quic` | не слать fake QUIC Initial | off |
| `--udplen` | padding UDP payload (+N / -N байт) | `0` |
| `--verbose` | логировать каждый обработанный поток | off |
| `--quiet` | вообще молчать, кроме ошибок | off |
| `--list` | список сервисов | — |
| `--filter` | свой WinDivert-фильтр | 443/80/8443 TCP + 443 UDP |

Останов — `Ctrl+C`.

## Поведение (важно)

Чтобы не ломать длительные соединения (Claude, стриминг, голосовые чаты), у
заглушки есть защитные механизмы:

1. **Обход один раз на соединение.** Десинхронизация применяется только к
   *первому* ClientHello потока. Транзмиты и keep-alive пакеты идут как есть.
   Без этого разрезали каждый пакет длинной сессии и соединение рвалось.
2. **Пропуск фрагментированных ClientHello.** Chrome/Claude с post-quantum
   (Kyber) шлют ClientHello на 2–3 сегмента. Если длина TLS-записи больше
   размера сегмента, пакет отправляется **без изменений** (иначе разбиение
   ломает рукопожатие).
3. **Пропуск IP-фрагментов.** Любой фрагментированный IP-пакет (MF=1 или
   ненулевое смещение) не содержит полного L4-сообщения и не десинхронизируется.
4. **Повторы только для трюков.** `--repeats=N` дублирует лишь сгенерированные
   fake/decoy-пакеты (низкий TTL или badseq). Реальные TCP-сегменты всегда
   отправляются один раз — дублирование с тем же seq бессмысленно и ломает
   порядок disorder.
5. **`--badseq` для split/disorder.** Добавляет decoy-пакет с битым sequence
   number перед реальными сегментами; реальные данные не портятся.
6. **Лог ограничен по времени** (не чаще раза в 400 мс в обычном режиме), чтобы
   блокирующий `printf` не забивал очередь WinDivert и не терял пакеты при
   активном трафике. `--verbose` для диагностики, `--quiet` — тишина.

Стратегии для AI-сервисов (Anthropic/Claude, Gemini, Copilot и др.) —
консервативные: `disorder` без повторов и без badseq, потому что Cloudflare
жестко реагирует на мульти-повторы и битый seq.

## Структура

```
src/csum.*      контрольные суммы (RFC 1071)
src/tls.*       парсер TLS ClientHello → SNI
src/http.*      парсер HTTP-запроса → Host
src/quic.*      парсер QUIC Initial + генератор фейкового Initial
src/packet.*    разбор/пересборка IP/TCP/UDP, IPv4+IPv6
src/desync.*    стратегии TCP/HTTP/QUIC десинхронизации
src/services.*  список сервисов и per-service стратегии
src/flow.*      кэш потоков (desync один раз на соединение)
src/windivert_dyn.*  рантайм-загрузка WinDivert.dll (единый exe без import-DLL)
src/main.cpp    WinDivert-цикл + CLI
scripts/        make-release.ps1 (релизный архив), sync-to-d.ps1 (синк в D:)
tests/          тесты (checksum, SNI, HTTP, QUIC, flow, матчинг сервисов)
```

## QUIC (HTTP/3)

Как и nfqws, обход **не расшифровывает** QUIC (payload защищён header
protection'ом). Применяются те же приёмы, что в zapret:

- **fake QUIC Initial** — перед реальным пакетом отправляется структурно
  корректный фейковый Initial (long header, version = v1, случайный DCID/SCID,
  правдоподобная длина, низкий TTL). DPI разбирает фейк и ошибается.
- **udplen** (`--udplen=N`) — добавить `N>0` нулевых байт к payload или срезать
  `N<0`, чтобы сломать DPI, ориентирующийся на размеры пакетов.

Парсер строгий: требует long header, тип Initial, ненулевую версию и корректные
длины DCID/SCID/token. Short header (1-RTT) и мусор не трогаются.

## Ограничения

- QUIC Initial **не расшифровывается** — hostname из CRYPTO-фрейма недоступен,
  поэтому hostlist для QUIC не применяется (в zapret для этого есть режим с
  ключами). Работает на уровне «фейк + реальный пакет».
- Нет обхода по IP (`ipset`) — только по SNI/Host.
- IPv6 поддержан в парсере, на живом трафике не тестировался.
