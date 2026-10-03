// Transformation stage: the packets that actually go on the wire must be valid and must
// deliver the original payload exactly once.
#include <set>
#include <string>
#include <vector>

#include "packet_builder.hpp"
#include "test_util.hpp"
#include "zc/csum.hpp"
#include "zc/quic.hpp"
#include "zc/strategy.hpp"
#include "zc/tls.hpp"

using namespace zctest;

namespace {

struct Fixture {
    std::vector<std::uint8_t> packet;
    zc::PacketLayout layout;

    explicit Fixture(std::span<const std::uint8_t> payload, TcpOptions options = {}) {
        packet = build_tcp(payload, options);
        (void)zc::parse_packet(packet, layout);
    }

    std::span<const std::uint8_t> payload_helpers() const {
        return std::span<const std::uint8_t>(packet.data() + layout.payload_offset,
                                      layout.payload_length);
    }
};

zc::PayloadHints tls_hints(const zc::TlsClientHello& hello) {
    zc::PayloadHints hints;
    hints.is_tls_client_hello = true;
    if (hello.has_sni) {
        hints.has_hostname = true;
        hints.host_offset = hello.sni_offset;
        hints.host_length = hello.sni_length;
    }
    return hints;
}

zc::StrategySettings defaults() {
    zc::StrategySettings settings;
    settings.fake_ttl = 4;
    settings.repeats = 1;
    settings.segments = 4;
    settings.fake_sni = "www.decoy.example";
    return settings;
}

// Every emitted packet must be a well formed IP/TCP datagram with correct checksums.
void check_outputs_are_valid(const std::vector<zc::OutPacket>& out, const char* label) {
    for (const zc::OutPacket& p : out) {
        zc::PacketLayout layout;
        ZC_CHECK_MSG(zc::parse_packet(p.bytes, layout) == zc::ParseStatus::ok, label);
        ZC_CHECK_MSG(layout.tcp, label);
        ZC_CHECK_MSG(zc::fold_sum(zc::ones_sum(
                        std::span<const std::uint8_t>(p.bytes).first(layout.ip_header_length))) == 0,
                    label);
        // TCP checksum must verify against a pseudo-header recomputation. Decoys with a
        // deliberately wrong checksum are excluded.
        if (p.trick) continue;
        auto copy = p.bytes;
        zc::PacketLayout rebuilt;
        if (zc::parse_packet(copy, rebuilt) != zc::ParseStatus::ok) continue;
        const std::uint16_t original = zc::read_be16(copy, layout.l4_offset + 16);
        ZC_REQUIRE(zc::fixup_packet(copy, rebuilt));
        ZC_CHECK_MSG(zc::read_be16(copy, layout.l4_offset + 16) == original, label);
    }
}

// UDP variant: parse validity plus a correct IPv4 header checksum.
void check_outputs_are_valid_udp(const std::vector<zc::OutPacket>& out, const char* label) {
    for (const zc::OutPacket& p : out) {
        zc::PacketLayout layout;
        ZC_CHECK_MSG(zc::parse_packet(p.bytes, layout) == zc::ParseStatus::ok, label);
        ZC_CHECK_MSG(layout.udp, label);
        ZC_CHECK_MSG(zc::fold_sum(zc::ones_sum(
                        std::span<const std::uint8_t>(p.bytes).first(layout.ip_header_length))) == 0,
                    label);
    }
}

// The concatenation of the real (non-decoy) payloads must equal the original payload.
void check_payload_preserved(const Fixture& fx, const std::vector<zc::OutPacket>& out,
                             const std::string& original_payload, const char* label) {
    std::string reassembled;
    std::set<std::uint32_t> sequences;
    for (const zc::OutPacket& p : out) {
        zc::PacketLayout layout;
        if (zc::parse_packet(p.bytes, layout) != zc::ParseStatus::ok) continue;
        if (p.trick) continue;
        const std::uint32_t seq = zc::read_be32(p.bytes, layout.l4_offset + 4);
        ZC_CHECK_MSG(sequences.insert(seq).second, "duplicate sequence number emitted");
        const std::string segment(
            reinterpret_cast<const char*>(p.bytes.data() + layout.payload_offset),
            layout.payload_length);
        // Place each real segment at its sequence offset.
        if (reassembled.size() < seq - fx.layout.tcp_sequence + segment.size()) {
            reassembled.resize(seq - fx.layout.tcp_sequence + segment.size(), '\0');
        }
        std::copy(segment.begin(), segment.end(),
                  reassembled.begin() + static_cast<std::ptrdiff_t>(seq - fx.layout.tcp_sequence));
    }
    ZC_CHECK_MSG(reassembled == original_payload,
                 std::string(label) + ": reassembled payload differs (got " +
                     std::to_string(reassembled.size()) + " of " +
                     std::to_string(original_payload.size()) + " bytes)");
}

void check_pass_is_identity() {
    const std::vector<std::uint8_t> payload(64, 0x41);
    const Fixture fx(payload);
    auto out = zc::transform_tcp(fx.packet, fx.layout, zc::Strategy::pass, defaults(), {},
                                 {std::string_view(), 1, {}});
    ZC_CHECK_EQ(out.size(), 1u);
    ZC_CHECK(!out[0].trick);
    // The bytes may differ only in the checksums the transform recomputes.
    zc::PacketLayout produced;
    ZC_REQUIRE(zc::parse_packet(out[0].bytes, produced) == zc::ParseStatus::ok);
    ZC_CHECK_EQ(produced.payload_length, payload.size());
    ZC_CHECK_EQ(produced.tcp_sequence, fx.layout.tcp_sequence);
    ZC_CHECK_EQ(produced.tcp_flags, fx.layout.tcp_flags);
    ZC_CHECK_EQ(produced.source_port, fx.layout.source_port);
    ZC_CHECK_EQ(produced.destination_port, fx.layout.destination_port);
    ZC_CHECK(std::vector<std::uint8_t>(out[0].bytes.begin() + static_cast<std::ptrdiff_t>(
                                         produced.payload_offset),
                                     out[0].bytes.end()) == payload);
    ZC_CHECK(zc::fold_sum(zc::ones_sum(
                std::span<const std::uint8_t>(out[0].bytes).first(produced.ip_header_length))) ==
             0u);
}

void check_split() {
    const std::vector<std::uint8_t> payload(100, 0x41);
    const Fixture fx(payload);
    zc::StrategySettings settings = defaults();
    settings.split_position = 40;
    auto out = zc::transform_tcp(fx.packet, fx.layout, zc::Strategy::split, settings, {},
                                 {std::string_view(), 1, {}});
    ZC_CHECK_EQ(out.size(), 2u);
    check_outputs_are_valid(out, "split");
    check_payload_preserved(fx, out, std::string(100, '\x41'), "split");
    // The cut must land exactly where it was asked to.
    zc::PacketLayout first;
    ZC_REQUIRE(zc::parse_packet(out[0].bytes, first) == zc::ParseStatus::ok);
    ZC_CHECK_EQ(first.payload_length, 40u);
}

void check_disorder_reverses_order() {
    const std::vector<std::uint8_t> payload(100, 0x41);
    const Fixture fx(payload);
    zc::StrategySettings settings = defaults();
    settings.split_position = 40;
    auto out = zc::transform_tcp(fx.packet, fx.layout, zc::Strategy::disorder, settings, {},
                                 {std::string_view(), 1, {}});
    ZC_CHECK_EQ(out.size(), 2u);
    check_outputs_are_valid(out, "disorder");
    // The segment carrying the tail is sent first.
    zc::PacketLayout head;
    ZC_REQUIRE(zc::parse_packet(out[0].bytes, head) == zc::ParseStatus::ok);
    ZC_CHECK_EQ(head.payload_length, 60u);
    check_payload_preserved(fx, out, std::string(100, '\x41'), "disorder");
}

void check_multisplit() {
    const std::vector<std::uint8_t> payload(200, 0x42);
    const Fixture fx(payload);
    zc::StrategySettings settings = defaults();
    settings.segments = 5;
    settings.split_position = 20;
    auto out = zc::transform_tcp(fx.packet, fx.layout, zc::Strategy::multisplit, settings, {},
                                 {std::string_view(), 1, {}});
    ZC_CHECK_EQ(out.size(), 5u);
    check_outputs_are_valid(out, "multisplit");
    check_payload_preserved(fx, out, std::string(200, '\x42'), "multisplit");

    auto disorder = zc::transform_tcp(fx.packet, fx.layout, zc::Strategy::multidisorder,
                                      settings, {}, {std::string_view(), 1, {}});
    ZC_CHECK_EQ(disorder.size(), 5u);
    check_payload_preserved(fx, disorder, std::string(200, '\x42'), "multidisorder");
}

void check_fake_produces_a_valid_decoy() {
    const auto hello_bytes = build_client_hello("real.example");
    const Fixture fx(hello_bytes);
    const zc::TlsClientHello hello = zc::parse_tls(fx.payload_helpers());
    const auto hints = tls_hints(hello);
    ZC_CHECK(hints.has_hostname);

    zc::StrategySettings settings = defaults();
    settings.fooling_badseq = true;
    settings.fooling_badsum = true;
    auto out = zc::transform_tcp(fx.packet, fx.layout, zc::Strategy::fake_multidisorder,
                                 settings, hints, {"real.example", 7, 0});
    ZC_CHECK(out.size() >= 2);
    ZC_CHECK(out.front().trick);
    check_outputs_are_valid(out, "fake-multidisorder");
    check_payload_preserved(fx, out, std::string(hello_bytes.begin(), hello_bytes.end()),
                            "fake-multidisorder");

    // The decoy must have a different hostname of the same length.
    zc::PacketLayout decoy_layout;
    ZC_REQUIRE(zc::parse_packet(out.front().bytes, decoy_layout) == zc::ParseStatus::ok);
    const auto decoy_hello = zc::parse_tls(
        std::span<const std::uint8_t>(out.front().bytes).subspan(decoy_layout.payload_offset,
                                                                decoy_layout.payload_length));
    ZC_CHECK(decoy_hello.has_sni);
    ZC_CHECK(decoy_hello.sni != "real.example");
    ZC_CHECK_EQ(decoy_hello.sni_length, hello.sni_length);
    ZC_CHECK(decoy_hello.hello_complete);

    // Lower TTL and poisoned sequence number.
    ZC_CHECK_EQ(out.front().bytes[8], 4u);
    const std::uint32_t decoy_seq =
        zc::read_be32(out.front().bytes, decoy_layout.l4_offset + 4);
    ZC_CHECK(decoy_seq != fx.layout.tcp_sequence);
}

void check_fake_without_sni_builds_a_valid_clienthello() {
    // A ClientHello with no usable SNI: the decoy must be a freshly built, internally
    // consistent ClientHello rather than a copy of bytes we could not parse.
    const auto hello_bytes = build_client_hello("", true, false);
    const Fixture fx(hello_bytes);
    zc::PayloadHints hints;
    hints.is_tls_client_hello = true;

    zc::StrategySettings settings = defaults();
    settings.fake_ttl = 3;
    auto out = zc::transform_tcp(fx.packet, fx.layout, zc::Strategy::fake, settings, hints,
                                 {std::string_view(), 9, {}});
    ZC_CHECK_EQ(out.size(), 2u);
    check_outputs_are_valid(out, "fake-no-sni");
    check_payload_preserved(fx, out, std::string(hello_bytes.begin(), hello_bytes.end()),
                            "fake-no-sni");

    zc::PacketLayout decoy_layout;
    ZC_REQUIRE(zc::parse_packet(out[0].bytes, decoy_layout) == zc::ParseStatus::ok);
    const auto decoy_hello = zc::parse_tls(
        std::span<const std::uint8_t>(out[0].bytes)
            .subspan(decoy_layout.payload_offset, decoy_layout.payload_length));
    ZC_CHECK(decoy_hello.is_client_hello);
    ZC_CHECK(decoy_hello.hello_complete);
    ZC_CHECK(decoy_hello.has_sni);
    ZC_CHECK_EQ(decoy_hello.sni, std::string("www.decoy.example"));
    // The record length must match the bytes we emitted.
    ZC_CHECK_EQ(decoy_hello.record_length, decoy_layout.payload_length);
}

void check_repeats_only_duplicate_decoys() {
    const auto hello_bytes = build_client_hello("repeat.example");
    const Fixture fx(hello_bytes);
    const auto hints = tls_hints(zc::parse_tls(fx.payload_helpers()));
    zc::StrategySettings settings = defaults();
    settings.repeats = 3;
    auto out = zc::transform_tcp(fx.packet, fx.layout, zc::Strategy::fake_multidisorder,
                                 settings, hints, {"repeat.example", 3, 0});
    int decoys = 0;
    int reals = 0;
    for (const zc::OutPacket& p : out) {
        if (p.trick) {
            ++decoys;
        } else {
            ++reals;
        }
    }
    ZC_CHECK_EQ(decoys, 3);
    ZC_CHECK(reals >= 2);
    check_payload_preserved(fx, out, std::string(hello_bytes.begin(), hello_bytes.end()),
                            "repeats");
}

void check_degenerate_payloads() {
    zc::StrategySettings settings = defaults();
    settings.split_position = 1;
    // A one-byte payload cannot be split.
    const Fixture tiny(std::vector<std::uint8_t>{0x42});
    auto out = zc::transform_tcp(tiny.packet, tiny.layout, zc::Strategy::split, settings, {},
                                 {std::string_view(), 1, {}});
    // Fail open: exactly the original packet comes back.
    ZC_CHECK_EQ(out.size(), 1u);
    ZC_CHECK(out[0].bytes == tiny.packet);
    ZC_CHECK(!out[0].trick);

    // A split position beyond the payload must not overflow anything.
    const Fixture medium(std::vector<std::uint8_t>(10, 0x43));
    zc::StrategySettings too_far = defaults();
    too_far.split_position = 1000;
    auto clamped = zc::transform_tcp(medium.packet, medium.layout, zc::Strategy::split,
                                     too_far, {}, {std::string_view(), 1, {}});
    check_outputs_are_valid(clamped, "split-clamped");
    check_payload_preserved(medium, clamped, std::string(10, '\x43'), "split-clamped");

    // An empty payload yields the original untouched.
    const Fixture empty(std::vector<std::uint8_t>{});
    auto none = zc::transform_tcp(empty.packet, empty.layout, zc::Strategy::multidisorder,
                                  settings, {}, {std::string_view(), 1, {}});
    ZC_CHECK_EQ(none.size(), 1u);
    ZC_CHECK(none[0].bytes == empty.packet);
}

void check_split_lands_inside_the_hostname() {
    const auto hello_bytes = build_client_hello("split-inside.example");
    const Fixture fx(hello_bytes);
    const auto hints = tls_hints(zc::parse_tls(fx.payload_helpers()));
    ZC_REQUIRE(hints.has_hostname);
    zc::StrategySettings settings = defaults();
    settings.split_position = -1;  // automatic
    auto out = zc::transform_tcp(fx.packet, fx.layout, zc::Strategy::split, settings, hints,
                                 {std::string_view(), 1, {}});
    ZC_REQUIRE(out.size() == 2);
    zc::PacketLayout first;
    ZC_REQUIRE(zc::parse_packet(out[0].bytes, first) == zc::ParseStatus::ok);
    const std::size_t expected = hints.host_offset + hints.host_length / 2;
    ZC_CHECK_EQ(first.payload_length, expected);
    // The cut must be strictly inside the hostname.
    ZC_CHECK(expected > hints.host_offset);
    ZC_CHECK(expected < hints.host_offset + hints.host_length);
}

void check_udp_length_delta() {
    const std::vector<std::uint8_t> payload(500, 0x44);
    const Fixture fx(payload, TcpOptions{});
    std::vector<std::uint8_t> udp_packet = build_udp(payload);
    zc::PacketLayout udp_layout;
    ZC_REQUIRE(zc::parse_packet(udp_packet, udp_layout) == zc::ParseStatus::ok);

    zc::PayloadHints hints;
    auto padded = zc::transform_udp(udp_packet, udp_layout, zc::Strategy::pass, defaults(),
                                    hints, {}, 20);
    ZC_CHECK_EQ(padded.size(), 1u);
    zc::PacketLayout padded_layout;
    ZC_CHECK(zc::parse_packet(padded[0].bytes, padded_layout) == zc::ParseStatus::ok);
    ZC_CHECK_EQ(padded_layout.payload_length, payload.size() + 20);
    ZC_CHECK(zc::fold_sum(zc::ones_sum(
                std::span<const std::uint8_t>(padded[0].bytes).first(20))) == 0);

    auto trimmed = zc::transform_udp(udp_packet, udp_layout, zc::Strategy::pass, defaults(),
                                     hints, {}, -20);
    ZC_CHECK_EQ(trimmed.size(), 1u);
    zc::PacketLayout trimmed_layout;
    ZC_CHECK(zc::parse_packet(trimmed[0].bytes, trimmed_layout) == zc::ParseStatus::ok);
    ZC_CHECK_EQ(trimmed_layout.payload_length, payload.size() - 20);

    // A trim that would leave nothing is refused and the packet passes through intact.
    const Fixture tiny_udp(std::vector<std::uint8_t>{0x11});
    std::vector<std::uint8_t> one_byte = build_udp(tiny_udp.payload_helpers());
    zc::PacketLayout one_layout;
    ZC_REQUIRE(zc::parse_packet(one_byte, one_layout) == zc::ParseStatus::ok);
    auto refuse = zc::transform_udp(one_byte, one_layout, zc::Strategy::pass, defaults(), {},
                                    {}, -4096);
    ZC_CHECK_EQ(refuse.size(), 1u);
    zc::PacketLayout refused_layout;
    ZC_REQUIRE(zc::parse_packet(refuse[0].bytes, refused_layout) == zc::ParseStatus::ok);
    // The single payload byte must survive: nothing was trimmed.
    ZC_CHECK_EQ(refused_layout.payload_length, 1u);
}

void check_quic_decoy() {
    const auto initial = zc::build_quic_client_initial("www.example.com", 1200, 42);
    ZC_REQUIRE(initial.size() == 1200);
    const std::vector<std::uint8_t> payload(initial.begin(), initial.end());
    auto packet = build_udp(payload);
    zc::PacketLayout udp_layout;
    ZC_REQUIRE(zc::parse_packet(packet, udp_layout) == zc::ParseStatus::ok);
    // Real traffic has valid checksums; make the baseline realistic so the checks below
    // are meaningful.
    ZC_REQUIRE(zc::fixup_packet(packet, udp_layout));
    ZC_CHECK_EQ(udp_layout.payload_length, payload.size());

    zc::PayloadHints hints;
    hints.is_quic_initial = true;
    zc::StrategySettings settings = defaults();
    settings.fake_ttl = 4;
    auto out = zc::transform_udp(packet, udp_layout, zc::Strategy::quic_fake, settings, hints,
                                {"www.example.com", 5, 0}, 0);
    ZC_CHECK(out.size() >= 2);
    ZC_CHECK(out.front().trick);
    check_outputs_are_valid_udp(out, "quic-fake");

    // The decoy must be a real, decodable client Initial with a different SNI.
    zc::PacketLayout decoy_layout;
    ZC_REQUIRE(zc::parse_packet(out.front().bytes, decoy_layout) == zc::ParseStatus::ok);
    const auto decoy_payload = std::span<const std::uint8_t>(out.front().bytes)
                                   .subspan(decoy_layout.payload_offset,
                                            decoy_layout.payload_length);
    const zc::QuicPacket decoy_packet = zc::parse_quic(decoy_payload);
    ZC_CHECK(decoy_packet.valid && decoy_packet.type == zc::QuicPacketType::initial);
    std::vector<std::uint8_t> frames;
    std::uint64_t pn = 0;
    ZC_REQUIRE(zc::decrypt_quic_initial(decoy_payload, decoy_packet, 0, frames, pn));
    zc::CryptoStream stream;
    stream.adopt_connection(decoy_packet.version,
                            decoy_payload.subspan(decoy_packet.dcid_offset,
                                                  decoy_packet.dcid_length));
    stream.add_frames(frames);
    std::string sni;
    ZC_CHECK(stream.client_hello_sni(sni));
    ZC_CHECK_EQ(sni, std::string("www.decoy.example"));
    ZC_CHECK(out.front().bytes[8] < 64);  // TTL was lowered
}

void run() {
    check_pass_is_identity();
    check_split();
    check_disorder_reverses_order();
    check_multisplit();
    check_fake_produces_a_valid_decoy();
    check_fake_without_sni_builds_a_valid_clienthello();
    check_repeats_only_duplicate_decoys();
    check_degenerate_payloads();
    check_split_lands_inside_the_hostname();
    check_udp_length_delta();
    check_quic_decoy();
}

}  // namespace

ZC_TEST_MAIN("strategy", run)
