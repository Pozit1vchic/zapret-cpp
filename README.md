# zapret-cpp 2.0

Native Windows DPI-desynchronization engine written in C++17 and built around WinDivert.
It is designed around **generic web traffic first**: unknown TLS/HTTP hosts use a fallback
strategy, while built-in profiles and user rules can tune individual domains without
recompiling the program.

> This project is independent from Flowseal/zapret-discord-youtube and bol-van/zapret.
> It uses similar DPI-desynchronization ideas, but this repository contains its own C++
> packet/TLS/HTTP/QUIC parsing and strategy implementation.

## What changed in 2.0

- Generic TLS/HTTP fallback for unknown websites instead of requiring a fixed site list.
- External `config/rules.txt`, hostlists and excludes with domain-suffix matching.
- Longest-suffix rule/profile selection, so specialized domains beat broad ecosystems.
- Correct TLS ClientHello bounds checking and safe handling of partial ClientHello records.
- HTTP parser walks real header boundaries and normalizes hostname, port and bracketed IPv6.
- QUIC Initial parser uses RFC variable-length integers and distinguishes QUIC v1/v2 types.
- IPv4 total-length validation, IPv6 extension-header walking and UDP length validation.
- Fixed flow cache: it now actually suppresses repeat desync of the same TCP flow and evicts
  the oldest entry instead of clearing the entire cache.
- Fixed WinDivert error handling: Windows `GetLastError()` is used; no nonexistent
  `WinDivertGetLastError` call or null function-pointer crash.
- Full opaque `WINDIVERT_ADDRESS` metadata is preserved for reinjection.
- Ctrl+C shuts down a blocking WinDivert receive cleanly.
- `fake-auto` chooses a deterministic decoy host; `--fake-rnd` changes only
  `ClientHello.random` instead of corrupting TLS framing.
- Segment flags are corrected: FIN/PSH stay on the logical last real segment.
- Built-in UAC manifest requests administrator rights.
- Core is a separate portable library; tests build and run on non-Windows systems too.

## Protocol scope

| Traffic | Default behavior |
|---|---|
| TLS over TCP | Generic fallback for any recognizable TLS ClientHello; clear SNI enables domain rules/profiles |
| HTTP/1.x | Generic fallback for any request with a Host header |
| QUIC/HTTP3 UDP 443 | Generic QUIC v1/v2 Initial desync |
| TLS with ECH/no clear SNI | Generic fallback still applies, but hostname-specific rules cannot be selected |
| Arbitrary non-web protocols | Passed through |

`--listed` intentionally disables QUIC handling because this engine does not decrypt QUIC/TLS
and therefore cannot know the hostname safely in listed-only mode.

## Build on Windows

Requirements:

- Windows 10/11 x64
- CMake 3.16+
- Ninja (recommended)
- A C++17 compiler (MSVC, MinGW-w64 or clang/llvm-mingw)

The WinDivert SDK needed at runtime is already under `third_party/windivert/`.

```powershell
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
```

For a ready-to-copy release directory and ZIP:

```powershell
pwsh -File scripts/make-release.ps1 -Version v2.0.0
```

The release script always builds from the current source; it never reuses the stale binary that
was present in the old archive.

## Quick start

Run an elevated terminal:

```powershell
.\zapret-cpp.exe
```

Useful modes:

```powershell
# inspect all outbound TCP payload ports instead of only common web ports
.\zapret-cpp.exe --all-tcp

# force one strategy globally
.\zapret-cpp.exe --strategy=fake-auto --badseq --repeats=2

# listed-only mode: built-ins + rules + this hostlist
.\zapret-cpp.exe --hostlist=lists\my-sites.txt

# custom per-domain rules and excludes
.\zapret-cpp.exe --rules=config\rules.txt --exclude=lists\exclude.txt

# local installation diagnostics
.\zapret-cpp.exe --check
```

Use `--help` for every option and `--list` for built-in domain profiles.

## Rules

`config/rules.txt` is auto-loaded beside the executable. Syntax:

```text
DOMAIN STRATEGY [key=value ...]
```

Supported keys are `split`, `ttl`, `repeats`, `segs`, `badseq`, `rnd`, and `fake-sni`.
The **longest matching suffix wins**.

```text
example.com fake-auto ttl=4 repeats=2 badseq=1
video.example.com multidisorder segs=6 split=-1
```

Domain list files accept plain suffixes, `*.example.com`, `||example.com^`, and common hosts-file
forms such as `0.0.0.0 example.com`.

## Strategies

- `split` — send the real TCP payload in two in-order pieces.
- `disorder` — send the second real segment before the first.
- `multidisorder` — split into 2–16 real segments and transmit in reverse order.
- `fake` — send a low-TTL/bad-sequence decoy before the real packet.
- `fake-multidisorder` — decoy plus multidisorder real payload.
- `fake-auto` — same pipeline with an automatically selected syntactically valid decoy SNI.

No single strategy is guaranteed to work against every DPI implementation or ISP. Start with the
default, then tune a domain in `config/rules.txt` if a particular network needs a different method.

## Safety / operational notes

- `--filter` is an advanced raw WinDivert filter override. A bad filter can capture much more
  traffic than intended.
- Low fake TTL is topology-dependent. If the decoy reaches the real server it can break a
  connection; `badseq=1` can provide an additional rejection mechanism.
- This is packet manipulation software. Keep a second elevated terminal available so you can
  terminate it if a custom strategy/filter behaves badly.
- Use it only where you are authorized to alter traffic on the machine/network.

## Tests

The current logic suite covers TLS, partial ClientHello, fake SNI construction, HTTP, QUIC v1/v2,
flow cache behavior, IPv4 fragmentation rejection, IPv6 extension headers, checksums, domain rules,
service specificity and desync packet generation. It is also run under AddressSanitizer and
UndefinedBehaviorSanitizer during local audit.

See `AUDIT.md` for the detailed repair list and remaining limitations.
