# zapret-cpp 2.0 audit

## Result

The uploaded project was treated as untrusted generated code and re-audited rather than patched
only until its original tests became green. The packet-processing core was substantially rewritten.

Local verification completed in this environment:

- CMake Debug build of the portable core: **PASS**
- Logic assertions: **70/70 PASS**
- AddressSanitizer + UndefinedBehaviorSanitizer: **PASS**
- Random parser fuzz-smoke (TLS/HTTP/QUIC/IP): **200,000 inputs, PASS**
- `ctest`: **PASS**

A Windows cross-compiler is not installed in this Linux sandbox, so the final WinDivert executable
was not falsely presented as rebuilt here. `scripts/make-release.ps1` builds it from source on a
Windows compiler and stages the matching WinDivert runtime. CI configuration also includes a native
Windows build job.

## Critical defects fixed

1. **Invalid WinDivert API call / crash path**
   - Old code tried to dynamically resolve `WinDivertGetLastError`, which WinDivert does not export.
   - Receive/send failure could therefore call a null function pointer.
   - New code uses Windows `GetLastError()` and validates every dynamically loaded function.

2. **Flow cache did not implement its documented behavior**
   - The return value of `seen_and_mark()` was ignored, so retransmitted ClientHello/HTTP requests
     were desynchronized again despite the claimed one-desync-per-flow behavior.
   - The result is now respected and FIN/RST can forget a flow.
   - Capacity eviction now removes the oldest entry instead of flushing the whole cache.

3. **Incorrect QUIC Initial parsing**
   - Token Length and Length were treated as fixed byte fields.
   - New parser implements QUIC variable-length integers, validates CID sizes and packet bounds,
     supports QUIC v1 and v2 Initial type mappings, and refuses to guess unknown version mappings.

4. **Fake TLS corruption**
   - Old randomization could destroy TLS framing.
   - New `--fake-rnd` changes only the 32-byte ClientHello random field.
   - Fake SNI replacement keeps exactly the original byte length and produces legal DNS labels,
     including lengths that cross the 63-byte label boundary.

5. **`fake-auto` was not actually automatic**
   - It previously shared the same effective path as another fake strategy.
   - It now deterministically selects a decoy hostname and length-fits it safely.

6. **HTTP false positives**
   - Old parsing could see `host:` inside another header value.
   - New parser is request-line/header-boundary aware and handles ports and bracketed IPv6.

7. **Packet parser robustness**
   - Added IPv4 total-length validation and fragmented-packet rejection.
   - Added IPv6 payload-length validation and common extension-header traversal.
   - Added UDP length validation and correct upper-layer checksum lengths through IPv6 extensions.

8. **Service/profile collisions**
   - Profile lookup now chooses the longest matching domain suffix.
   - Specialized YouTube/Discord CDN rules can no longer be accidentally swallowed by a broad
     ecosystem profile with an equal/shorter suffix.

9. **WinDivert reinjection metadata**
   - The full opaque `WINDIVERT_ADDRESS` is preserved instead of reconstructing only two flags.
   - This keeps interface/layer metadata needed for correct reinjection.

10. **Blocking shutdown**
    - Ctrl+C now calls WinDivert shutdown for the receive direction so the blocking receive exits.

## Architecture added

- `zapret_core` portable static library separated from Windows entry/WinDivert glue.
- User domain rules (`src/rules.*`).
- Auto-loaded `config/rules.txt` and `lists/exclude.txt`.
- Optional external hostlists and longest-suffix matching.
- Generic unknown-site fallback instead of a closed hardcoded allowlist.
- `--check`, `--version`, `--fallback`, `--all-tcp`, `--no-builtins`, `--no-auto-files`.
- UAC manifest.
- Clean release staging and SHA-256 checksum generation.
- Linux logic-test and Windows build jobs in GitHub Actions.

## Known limitations (not hidden as “fixed”)

- The engine does **not** reconstruct a ClientHello split across multiple TCP packets. It can still
  recognize a TLS record prefix and apply generic splitting, but hostname-specific SNI rules require
  the SNI bytes to be present in the captured packet.
- QUIC hostname/SNI is encrypted. Therefore QUIC is generic-only; listed mode disables it rather
  than pretending to know the hostname.
- No DPI strategy can be proven universally best without testing against the target ISP/DPI.
- This release does not yet contain Flowseal-style online list updates, automatic provider strategy
  benchmarking, or a Windows service-manager UI. Those are management features, not packet-core
  correctness, and claiming parity would be misleading.
- Only common QUIC v1/v2 Initial forms are deliberately accepted; unknown future version type
  mappings are rejected until explicitly implemented.

## Release rule

Do not ship an executable from an older build directory with newer source. Always build with
`scripts/make-release.ps1`; it deletes/recreates the staging directory and packages only the fresh
build output plus the matching runtime/config/documentation files.
