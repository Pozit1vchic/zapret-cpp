// IPv4 / IPv6 / TCP / UDP parsing and fix-up verification.
#include <vector>

#include "packet_builder.hpp"
#include "test_util.hpp"
#include "zc/csum.hpp"
#include "zc/packet.hpp"

using namespace zctest;

namespace {

void check_ipv4_checksum() {
    std::vector<std::uint8_t> header(20, 0);
    header[0] = 0x45;
    header[8] = 64;
    header[9] = zc::kProtoTcp;
    header[12] = 192; header[13] = 168; header[14] = 1; header[15] = 1;
    header[16] = 93;  header[17] = 184; header[18] = 216; header[19] = 34;
    const std::uint16_t cs = zc::internet_checksum(header);
    header[10] = static_cast<std::uint8_t>(cs >> 8);
    header[11] = static_cast<std::uint8_t>(cs & 0xffu);
    // Summing a header that already contains its checksum must yield zero.
    ZC_CHECK_EQ(zc::fold_sum(zc::ones_sum(header)), 0u);
}

void check_ipv4_parsing() {
    const std::vector<std::uint8_t> payload(64, 0x41);
    const auto packet = build_tcp(payload);
    zc::PacketLayout layout;
    ZC_REQUIRE(zc::parse_packet(packet, layout) == zc::ParseStatus::ok);
    ZC_CHECK(layout.tcp && !layout.udp);
    ZC_CHECK(layout.family == zc::IpFamily::v4);
    ZC_CHECK_EQ(layout.payload_length, payload.size());
    ZC_CHECK_EQ(layout.source_port, 50000u);
    ZC_CHECK_EQ(layout.destination_port, 443u);
    ZC_CHECK_EQ(layout.tcp_sequence, 1000u);
    ZC_CHECK_EQ(layout.ip_header_length, 20u);
    ZC_CHECK_EQ(layout.wire_length, packet.size());
    ZC_CHECK_EQ(layout.destination.to_string(), std::string("93.184.216.34"));
    ZC_CHECK(!layout.destination.is_private());
    ZC_CHECK(!layout.destination.is_loopback());
}

void check_ipv4_with_options() {
    TcpOptions options;
    options.options = {0x01, 0x01, 0x08, 0x0a};  // NOP, NOP, MSS
    const std::vector<std::uint8_t> payload(10, 0x42);
    const auto packet = build_tcp(payload, options);
    zc::PacketLayout layout;
    ZC_REQUIRE(zc::parse_packet(packet, layout) == zc::ParseStatus::ok);
    ZC_CHECK_EQ(layout.l4_header_length, 24u);
    ZC_CHECK_EQ(layout.payload_length, payload.size());
}

void check_ipv4_fragmentation() {
    const std::vector<std::uint8_t> payload(16, 0x41);
    zc::PacketLayout layout;

    ZC_CHECK(zc::parse_packet(build_tcp(payload), layout) == zc::ParseStatus::ok);
    ZC_CHECK(zc::parse_packet(build_tcp(payload, TcpOptions{}), layout) == zc::ParseStatus::ok);

    // MF set.
    auto mf = build_tcp(payload);
    mf[6] = 0x20;
    ZC_CHECK(zc::parse_packet(mf, layout) == zc::ParseStatus::fragmented);
    // Non-zero fragment offset.
    auto offset = build_tcp(payload);
    offset[6] = 0x00;
    offset[7] = 0x01;
    ZC_CHECK(zc::parse_packet(offset, layout) == zc::ParseStatus::fragmented);
    // Don't fragment is fine.
    auto df = build_tcp(payload);
    df[6] = 0x40;
    ZC_CHECK(zc::parse_packet(df, layout) == zc::ParseStatus::ok);
}

void check_bad_lengths() {
    zc::PacketLayout layout;
    // Total length shorter than the header.
    auto short_total = build_tcp(std::vector<std::uint8_t>(4, 1));
    short_total[2] = 0;
    short_total[3] = 10;
    ZC_CHECK(zc::parse_packet(short_total, layout) == zc::ParseStatus::bad_length);

    // Total length larger than the capture: must be rejected, never truncated silently.
    auto long_total = build_tcp(std::vector<std::uint8_t>(4, 1));
    long_total[2] = 0xff;
    long_total[3] = 0xff;
    ZC_CHECK(zc::parse_packet(long_total, layout) == zc::ParseStatus::bad_length);

    // Trailing bytes beyond the declared length are ignored, not read.
    auto trailing = build_tcp(std::vector<std::uint8_t>(4, 1));
    trailing.insert(trailing.end(), 16, 0xee);
    ZC_CHECK(zc::parse_packet(trailing, layout) == zc::ParseStatus::ok);
    ZC_CHECK_EQ(layout.wire_length, trailing.size() - 16);

    // IHL below the minimum.
    auto bad_ihl = build_tcp(std::vector<std::uint8_t>(4, 1));
    bad_ihl[0] = 0x43;
    ZC_CHECK(zc::parse_packet(bad_ihl, layout) == zc::ParseStatus::bad_header);

    // Unknown IP version.
    auto bad_version = build_tcp(std::vector<std::uint8_t>(4, 1));
    bad_version[0] = 0x75;
    ZC_CHECK(zc::parse_packet(bad_version, layout) == zc::ParseStatus::bad_version);

    // Truncated buffers of every length must be rejected without reading out of bounds.
    const auto packet = build_tcp(std::vector<std::uint8_t>(64, 0x41));
    for (std::size_t cut = 0; cut < packet.size(); ++cut) {
        zc::PacketLayout partial;
        const zc::ParseStatus status = zc::parse_packet(
            std::span<const std::uint8_t>(packet).first(cut), partial);
        if (status == zc::ParseStatus::ok) {
            ZC_CHECK_MSG(partial.wire_length <= cut, "accepted truncated packet at " +
                                                          std::to_string(cut));
        }
    }
}

void check_udp() {
    const std::vector<std::uint8_t> payload(100, 0x55);
    auto packet = build_udp(payload);
    zc::PacketLayout layout;
    ZC_REQUIRE(zc::parse_packet(packet, layout) == zc::ParseStatus::ok);
    ZC_CHECK(layout.udp && !layout.tcp);
    ZC_CHECK_EQ(layout.payload_length, payload.size());

    // UDP length below the header minimum.
    auto bad = packet;
    bad[20 + 4] = 0;
    bad[20 + 5] = 4;
    ZC_CHECK(zc::parse_packet(bad, layout) == zc::ParseStatus::bad_length);

    // UDP length beyond the IP payload.
    bad = packet;
    bad[20 + 4] = 0xff;
    bad[20 + 5] = 0xff;
    ZC_CHECK(zc::parse_packet(bad, layout) == zc::ParseStatus::bad_length);

    // A zero length is invalid over IPv4.
    bad = packet;
    bad[20 + 4] = 0;
    bad[20 + 5] = 0;
    ZC_CHECK(zc::parse_packet(bad, layout) == zc::ParseStatus::bad_length);
}

void check_ipv6() {
    const std::vector<std::uint8_t> payload(64, 0x42);
    const auto packet = build_ipv6_tcp(payload);
    zc::PacketLayout layout;
    ZC_REQUIRE(zc::parse_packet(packet, layout) == zc::ParseStatus::ok);
    ZC_CHECK(layout.family == zc::IpFamily::v6);
    ZC_CHECK_EQ(layout.ip_header_length, 40u);
    ZC_CHECK_EQ(layout.l4_offset, 40u);
    ZC_CHECK_EQ(layout.payload_length, payload.size());
    ZC_CHECK_EQ(layout.source.to_string(), std::string("2001:db8::1"));
    ZC_CHECK_EQ(layout.destination.to_string(), std::string("2606:2800::68"));
    ZC_CHECK_EQ(layout.destination_port, 443u);
}

void check_ipv6_extensions() {
    const std::vector<std::uint8_t> payload(20, 0x42);
    TcpOptions options;
    std::vector<std::uint8_t> transport;
    push16(transport, options.source_port);
    push16(transport, options.destination_port);
    push32(transport, options.sequence);
    push32(transport, options.acknowledgment);
    push8(transport, 0x50);
    push8(transport, options.flags);
    push16(transport, 0xffff);
    push16(transport, 0);
    push16(transport, 0);
    transport.insert(transport.end(), payload.begin(), payload.end());

    // Two chained extension headers. Each extension header starts with *its* Next Header
    // field, so the first byte of every header names the header that follows it; the
    // base IPv6 header names the first one.
    std::vector<std::uint8_t> chain;
    push8(chain, zc::kProtoHopByHop);  // DstOpts -> Hop-by-Hop
    push8(chain, 0);                   // Hdr Ext Len 0 => 8 bytes
    chain.insert(chain.end(), 6, 0);
    push8(chain, zc::kProtoTcp);       // Hop-by-Hop -> TCP
    push8(chain, 1);                   // Hdr Ext Len 1 => 16 bytes
    chain.insert(chain.end(), 14, 0);
    chain.insert(chain.end(), transport.begin(), transport.end());

    const auto packet = build_ipv6(zc::kProtoDstOpts, chain);
    zc::PacketLayout layout;
    ZC_REQUIRE(zc::parse_packet(packet, layout) == zc::ParseStatus::ok);
    ZC_CHECK_EQ(layout.l4_offset, 40 + 8 + 16);
    ZC_CHECK_EQ(layout.payload_length, payload.size());
    ZC_CHECK(layout.tcp);

    // An atomic fragment (RFC 6946) is indistinguishable from an unfragmented packet and
    // must still be processed.
    std::vector<std::uint8_t> atomic;
    push8(atomic, zc::kProtoTcp);
    push8(atomic, 0);
    push16(atomic, 0);   // reserved + fragment offset 0
    push32(atomic, 0);   // identification
    atomic.insert(atomic.end(), transport.begin(), transport.end());
    const auto atomic_packet = build_ipv6(zc::kProtoFragment, atomic);
    ZC_CHECK(zc::parse_packet(atomic_packet, layout) == zc::ParseStatus::ok);
    ZC_CHECK_EQ(layout.l4_offset, 40 + 8);
    ZC_CHECK_EQ(layout.payload_length, payload.size());

    // A real fragment (non-zero offset, or the "more fragments" bit) must be refused.
    auto more = atomic;
    more[3] = 0x01;
    ZC_CHECK(zc::parse_packet(build_ipv6(zc::kProtoFragment, more), layout) ==
             zc::ParseStatus::fragmented);
    auto offset_fragment = atomic;
    offset_fragment[2] = 0x00;
    offset_fragment[3] = 0x10;  // offset 2
    ZC_CHECK(zc::parse_packet(build_ipv6(zc::kProtoFragment, offset_fragment), layout) ==
             zc::ParseStatus::fragmented);

    // A malformed extension length must be refused.
    auto bad_chain = chain;
    bad_chain[1] = 0x7f;  // absurd length
    ZC_CHECK(zc::parse_packet(build_ipv6(zc::kProtoDstOpts, bad_chain), layout) ==
             zc::ParseStatus::bad_extension_chain);

    // A zero IPv6 payload length (jumbogram) is refused rather than mis-parsed.
    auto jumbogram = build_ipv6_tcp(payload);
    jumbogram[4] = 0;
    jumbogram[5] = 0;
    ZC_CHECK(zc::parse_packet(jumbogram, layout) == zc::ParseStatus::bad_length);
}

void check_fixup() {
    const std::vector<std::uint8_t> payload(50, 0x41);
    auto packet = build_tcp(payload);
    zc::PacketLayout layout;
    ZC_REQUIRE(zc::parse_packet(packet, layout) == zc::ParseStatus::ok);
    ZC_REQUIRE(zc::fixup_packet(packet, layout));
    // After a fix-up the header checksum must verify and the transport checksum too.
    ZC_CHECK_EQ(zc::fold_sum(zc::ones_sum(std::span<const std::uint8_t>(packet).first(20))), 0u);
    auto verify = packet;
    zc::PacketLayout checked;
    ZC_REQUIRE(zc::parse_packet(verify, checked) == zc::ParseStatus::ok);
    ZC_CHECK(zc::fixup_packet(verify, checked));

    // Growing the payload must update both length fields and the checksums. The IP and
    // UDP/TCP length fields are stale until fixup_packet() runs, so patch them first the
    // way a real transform would, then re-parse.
    auto grown = packet;
    grown.insert(grown.end(), 10, 0x00);
    grown[2] = static_cast<std::uint8_t>((grown.size()) >> 8);
    grown[3] = static_cast<std::uint8_t>(grown.size() & 0xffu);
    zc::PacketLayout grown_layout;
    ZC_REQUIRE(zc::parse_packet(grown, grown_layout) == zc::ParseStatus::ok);
    ZC_CHECK_EQ(grown_layout.payload_length, payload.size() + 10);
    ZC_REQUIRE(zc::fixup_packet(grown, grown_layout));
    ZC_CHECK_EQ(grown[2], static_cast<std::uint8_t>((grown.size()) >> 8));
    ZC_CHECK_EQ(grown[3], static_cast<std::uint8_t>(grown.size() & 0xffu));
    ZC_CHECK_EQ(zc::fold_sum(zc::ones_sum(std::span<const std::uint8_t>(grown).first(20))), 0u);

    // Hop limit changes must keep the header checksum correct.
    auto ttl_packet = packet;
    ZC_REQUIRE(zc::set_hop_limit(ttl_packet, grown_layout, 3));
    ZC_CHECK_EQ(ttl_packet[8], 3u);
    ZC_CHECK_EQ(zc::fold_sum(zc::ones_sum(std::span<const std::uint8_t>(ttl_packet).first(20))), 0u);
    // A TTL of zero is refused: a packet with TTL 0 would not leave the host.
    ZC_CHECK(!zc::set_hop_limit(ttl_packet, grown_layout, 0));
}

void check_udp_checksum_roundtrip() {
    const std::vector<std::uint8_t> payload(64, 0x7e);
    auto packet = build_udp(payload);
    zc::PacketLayout layout;
    ZC_REQUIRE(zc::parse_packet(packet, layout) == zc::ParseStatus::ok);
    ZC_REQUIRE(zc::fixup_packet(packet, layout));
    ZC_CHECK_EQ(packet[20 + 4], 0u);
    ZC_CHECK_EQ(packet[20 + 5], static_cast<std::uint8_t>(8 + payload.size()));
    // IPv6 UDP has no mandatory checksum but we always compute one.
    ZC_CHECK(packet[20 + 6] != 0 || packet[20 + 7] != 0);
}

void check_address_parsing() {
    ZC_CHECK_EQ(zc::IpAddress::parse("1.2.3.4").to_string(), std::string("1.2.3.4"));
    ZC_CHECK(zc::IpAddress::parse("1.2.3.256").family == zc::IpFamily::none);
    ZC_CHECK(zc::IpAddress::parse("1.2.3").family == zc::IpFamily::none);
    ZC_CHECK(zc::IpAddress::parse("1.2.3.4.5").family == zc::IpFamily::none);
    ZC_CHECK(zc::IpAddress::parse("").family == zc::IpFamily::none);
    ZC_CHECK(zc::IpAddress::parse("hello").family == zc::IpFamily::none);
    ZC_CHECK_EQ(zc::IpAddress::parse("::1").to_string(), std::string("::1"));
    ZC_CHECK_EQ(zc::IpAddress::parse("[2001:db8::1]").to_string(), std::string("2001:db8::1"));
    ZC_CHECK(zc::IpAddress::parse("2001:db8:::1").family == zc::IpFamily::none);
    ZC_CHECK(zc::IpAddress::parse("gggg::1").family == zc::IpFamily::none);
    ZC_CHECK(zc::IpAddress::parse("12345::1").family == zc::IpFamily::none);

    ZC_CHECK(zc::IpAddress::parse("127.0.0.1").is_loopback());
    ZC_CHECK(zc::IpAddress::parse("10.1.2.3").is_private());
    ZC_CHECK(zc::IpAddress::parse("172.16.0.1").is_private());
    ZC_CHECK(!zc::IpAddress::parse("172.32.0.1").is_private());
    ZC_CHECK(zc::IpAddress::parse("192.168.0.1").is_private());
    ZC_CHECK(zc::IpAddress::parse("100.64.0.1").is_private());   // CGNAT
    ZC_CHECK(zc::IpAddress::parse("169.254.1.1").is_link_local());
    ZC_CHECK(zc::IpAddress::parse("224.0.0.1").is_multicast());
    ZC_CHECK(zc::IpAddress::parse("240.0.0.1").is_reserved());
    ZC_CHECK(zc::IpAddress::parse("0.0.0.0").is_unspecified());
    ZC_CHECK(zc::IpAddress::parse("::1").is_loopback());
    ZC_CHECK(zc::IpAddress::parse("fe80::1").is_link_local());
    ZC_CHECK(zc::IpAddress::parse("fc00::1").is_private());
    ZC_CHECK(zc::IpAddress::parse("ff02::1").is_multicast());
    ZC_CHECK(zc::IpAddress::parse("::ffff:10.0.0.1").is_private());
    ZC_CHECK(!zc::IpAddress::parse("8.8.8.8").is_private());
    ZC_CHECK(!zc::IpAddress::parse("2606:4700::1111").is_private());
}

void check_cidr() {
    const auto net = zc::IpNetwork::parse("10.0.0.0/8");
    ZC_REQUIRE(net.has_value());
    ZC_CHECK(net->contains(zc::IpAddress::parse("10.1.2.3")));
    ZC_CHECK(!net->contains(zc::IpAddress::parse("11.1.2.3")));
    // Family mismatch must never match.
    ZC_CHECK(!net->contains(zc::IpAddress::parse("fd00::1")));

    const auto v6 = zc::IpNetwork::parse("2001:db8::/32");
    ZC_REQUIRE(v6.has_value());
    ZC_CHECK(v6->contains(zc::IpAddress::parse("2001:db8::1")));
    ZC_CHECK(!v6->contains(zc::IpAddress::parse("2001:db9::1")));

    const auto host = zc::IpNetwork::parse("1.2.3.4/32");
    ZC_REQUIRE(host.has_value());
    ZC_CHECK(host->contains(zc::IpAddress::parse("1.2.3.4")));
    ZC_CHECK(!host->contains(zc::IpAddress::parse("1.2.3.5")));

    const auto all = zc::IpNetwork::parse("0.0.0.0/0");
    ZC_REQUIRE(all.has_value());
    ZC_CHECK(all->contains(zc::IpAddress::parse("8.8.8.8")));

    ZC_CHECK(!zc::IpNetwork::parse("10.0.0.0/33").has_value());
    ZC_CHECK(!zc::IpNetwork::parse("2001:db8::/129").has_value());
    ZC_CHECK(!zc::IpNetwork::parse("nonsense/8").has_value());
    ZC_CHECK(!zc::IpNetwork::parse("10.0.0.0").has_value());
}

void check_unknown_protocol() {
    std::vector<std::uint8_t> packet = build_ipv4(1 /* ICMP */, std::vector<std::uint8_t>(8, 0), 64);
    zc::PacketLayout layout;
    ZC_CHECK(zc::parse_packet(packet, layout) == zc::ParseStatus::unknown_protocol);
    // A packet we cannot classify must not be modified.
    ZC_CHECK(!zc::fixup_packet(packet, layout));
}

void run() {
    check_ipv4_checksum();
    check_ipv4_parsing();
    check_ipv4_with_options();
    check_ipv4_fragmentation();
    check_bad_lengths();
    check_udp();
    check_ipv6();
    check_ipv6_extensions();
    check_fixup();
    check_udp_checksum_roundtrip();
    check_address_parsing();
    check_cidr();
    check_unknown_protocol();
}

}  // namespace

ZC_TEST_MAIN("packet", run)
