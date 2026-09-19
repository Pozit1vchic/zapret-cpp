# zapret-cpp

Клон zapret на C++: перехват исходящего TCP через WinDivert и обход DPI
десинхронизацией TLS ClientHello (split / disorder / fake-TTL).

Учебный проект — показывает, **как** работает обход DPI, на ~400 строках C++.

## Как это работает

1. WinDivert перехватывает исходящие TCP-пакеты (порты 443/80).
2. Парсер TLS достаёт из ClientHello позицию `server_name` (SNI).
3. Стратегия режет поток так, чтобы DPI не собрал SNI целиком:
   - **split** — отправить ClientHello двумя TCP-сегментами;
   - **disorder** — то же, но второй сегмент уходит первым (сбивает stateful DPI);
   - **fake** — отправить фейковый ClientHello с TTL ниже нужного, он умрёт в пути и до сервера не дойдёт, зато DPI «съест» подмену.

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
cmake -S . -B build -G Ninja
cmake --build build --target logic_test
./build/logic_test.exe
```

или вручную:

```sh
g++ -std=c++17 -Isrc tests/logic_test.cpp src/csum.cpp src/tls.cpp -o build/logic_test.exe
```

## Запуск

Нужны **права администратора** (WinDivert грузит драйвер). `WinDivert.dll` и
`WinDivert64.sys` должны лежать рядом с exe (CMake-сборка их не копирует —
скопируй вручную из `third_party/windivert/x64/`).

```sh
./zapret-cpp.exe --strategy=split
./zapret-cpp.exe --strategy=disorder
./zapret-cpp.exe --strategy=fake --ttl=4 --fake-sni=www.microsoft.com
```

Флаги:

| флаг | смысл | default |
|------|-------|---------|
| `--strategy` | `split` \| `disorder` \| `fake` | `split` |
| `--split` | смещение разреза, `-1` = авто (середина SNI) | `-1` |
| `--ttl` | TTL фейкового пакета | `4` |
| `--fake-sni` | подменный хост для `fake` | `www.microsoft.com` |
| `--filter` | свой WinDivert-фильтр | `outbound and tcp and (tcp.DstPort == 443 or tcp.DstPort == 80)` |

Останов — `Ctrl+C`.

## Структура

```
src/csum.*     контрольные суммы (RFC 1071)
src/tls.*      парсер TLS ClientHello → SNI
src/packet.*   разбор/пересборка IP/TCP пакета
src/desync.*   стратегии десинхронизации
src/main.cpp   WinDivert-цикл + CLI
tests/         тесты логики (checksum, SNI)
```

## Ограничения / куда копать дальше

- Сейчас правится только `server_name`; HTTPS через QUIC/UDP не трогается.
- Нет хоста-листа (whitelist по SNI) — режем всё подряд.
- IPv6 поддержан в парсере, но не тестировался.
- Идеи: авто-подбор стратегии, UDP/QUIC, десинк на уровне HTTP Host для порта 80.
