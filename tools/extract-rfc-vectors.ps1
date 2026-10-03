// Re-extract the RFC 9001 Appendix A.2 test vectors into tests/rfc9001_vectors.h.
//
// The RFC publishes the QUIC client Initial packet in hex form. Hand-copying it into a
// test is a transcription hazard (this project already got it wrong once), so the bytes
// are extracted mechanically from a local copy of the RFC text instead.
//
// Usage:
//   pwsh -File tools/extract-rfc-vectors.ps1 -RfcText path\to\rfc9001.txt
//
// The expected line ranges below are 1-based and correspond to the section markers
// shown in the comments; adjust them if you feed in a differently formatted copy.

param(
    [Parameter(Mandatory = $true)][string]$RfcText,
    [string]$Output = (Join-Path (Split-Path -Parent $PSScriptRoot) "tests\rfc9001_vectors.h")
)

$ErrorActionPreference = "Stop"

$lines = Get-Content -LiteralPath $RfcText

function Find-BlockStart {
    param([string]$Marker, [int]$From = 0)
    for ($i = $From; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match $Marker) { return $i }
    }
    throw "marker not found: $Marker"
}

function Get-HexBlock {
    param([int]$Start, [int]$Count)
    $hex = ($lines[$Start..($Start + $Count - 1)] | ForEach-Object { ($_ -replace '[^0-9a-fA-F]', '').ToLower() }) -join ''
    if ($hex.Length % 2 -ne 0) { throw "odd hex length at line $($Start + 1)" }
    return $hex
}

function ConvertTo-CppLiteral {
    param([string]$Hex)
    $out = @()
    for ($i = 0; $i -lt $Hex.Length; $i += 64) {
        $out += ('    "' + $Hex.Substring($i, [Math]::Min(64, $Hex.Length - $i)) + '"')
    }
    return ($out -join "`r`n")
}

# "The unprotected payload of this packet contains the following CRYPTO frame"
$framesStart = Find-BlockStart -Marker 'unprotected payload of this packet contains'
$cryptoFrame = Get-HexBlock -Start ($framesStart + 3) -Count 8

# "The resulting protected packet is:"
$protStart = Find-BlockStart -Marker 'resulting protected packet is'
$protected = Get-HexBlock -Start ($protStart + 2) -Count 37

Write-Host "crypto frame     : $($cryptoFrame.Length / 2) bytes"
Write-Host "protected packet : $($protected.Length / 2) bytes (RFC packet is 1200)"

$header = @"
// Generated from the text of RFC 9001 (Appendix A.2) by tools/extract-rfc-vectors.ps1.
// Do not hand-edit.
//
// The RFC publishes the client Initial packet in two pieces: the *unprotected* CRYPTO
// frame (the CRYPTO frame carrying the ClientHello, followed by PADDING) and the
// *protected* packet. This header holds both verbatim, plus the header-protection
// intermediate values, so tests/test_quic.cpp can re-encrypt the published plaintext
// and compare it byte for byte against the published ciphertext.
#pragma once

namespace zctest::rfc9001 {

// Client-chosen Destination Connection ID.
inline constexpr char kDcid[] = "8394c8f03e515708";

// RFC 9001 A.1 derived client Initial keys.
inline constexpr char kClientKey[] = "1f369613dd76d5467730efcbe3b1a22d";
inline constexpr char kClientIv[] = "fa044b2f42a3fd3b46fb255c";
inline constexpr char kClientHp[] = "9f50449e04a0e810283a1e9933adedd2";
inline constexpr char kInitialSecret[] =
    "7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44";
inline constexpr char kClientInitialSecret[] =
    "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea";

// RFC 9001 A.2 header protection intermediates.
inline constexpr char kSample[] = "d1b1c98dd7689fb8ec11d242b123dc9b";
inline constexpr char kMask[] = "437b9aec36";
inline constexpr char kProtectedHeader[] = "c000000001088394c8f03e5157080000449e7b9aec34";
inline constexpr char kUnprotectedHeader[] =
    "c300000001088394c8f03e5157080000449e00000002";

// The unprotected payload: one CRYPTO frame (offset 0, length 241) carrying the
// ClientHello, i.e. 245 bytes. The remaining bytes of the real 1162-byte payload are
// PADDING frames (single zero bytes) and are reproduced by the test.
inline constexpr char kCryptoFrame[] =
$(ConvertTo-CppLiteral -Hex $cryptoFrame);

// The protected packet: 18-byte header, 4-byte packet number and 1162 bytes of
// ciphertext. The trailing 16-byte AEAD tag is not part of this excerpt.
inline constexpr char kProtectedPacket[] =
$(ConvertTo-CppLiteral -Hex $protected);

}  // namespace zctest::rfc9001
"@

Set-Content -NoNewline -LiteralPath $Output -Value $header
Write-Host "wrote $Output"
