#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace zc {

struct AddressTag {
    bool outbound = false;
};

#pragma pack(push, 1)
struct IpHdr {
    std::uint8_t  ver_ihl;
    std::uint8_t  tos;
    std::uint16_t total_len;
    std::uint16_t id;
    std::uint16_t frag_off;
    std::uint8_t  ttl;
    std::uint8_t  proto;
    std::uint16_t checksum;
    std::uint32_t src;
    std::uint32_t dst;
};

struct Ipv6Hdr {
    std::uint32_t ver_tc_fl;
    std::uint16_t payload_len;
    std::uint8_t  next_header;
    std::uint8_t  hop_limit;
    std::uint8_t  src[16];
    std::uint8_t  dst[16];
};

struct TcpHdr {
    std::uint16_t src_port;
    std::uint16_t dst_port;
    std::uint32_t seq;
    std::uint32_t ack;
    std::uint8_t  data_off;
    std::uint8_t  flags;
    std::uint16_t window;
    std::uint16_t checksum;
    std::uint16_t urg_ptr;
};
#pragma pack(pop)

constexpr std::uint8_t TCP_FIN = 0x01;
constexpr std::uint8_t TCP_SYN = 0x02;
constexpr std::uint8_t TCP_RST = 0x04;
constexpr std::uint8_t TCP_PSH = 0x08;
constexpr std::uint8_t TCP_ACK = 0x10;
constexpr std::uint8_t TCP_URG = 0x20;
constexpr std::uint8_t IPPROTO_TCP_NUM = 6;

class Packet {
public:
    std::vector<std::uint8_t> bytes;
    AddressTag                addr{};

    bool parse();

    bool is_ipv4() const { return ipv4_; }
    bool is_ipv6() const { return ipv6_; }
    bool is_tcp() const { return tcp_; }

    IpHdr*    ip() { return ipv4_ ? reinterpret_cast<IpHdr*>(bytes.data()) : nullptr; }
    Ipv6Hdr*  ip6() { return ipv6_ ? reinterpret_cast<Ipv6Hdr*>(bytes.data()) : nullptr; }
    TcpHdr*   tcp() { return tcp_ ? reinterpret_cast<TcpHdr*>(bytes.data() + tcp_off_) : nullptr; }

    const IpHdr*  ip() const { return ipv4_ ? reinterpret_cast<const IpHdr*>(bytes.data()) : nullptr; }
    const Ipv6Hdr* ip6() const { return ipv6_ ? reinterpret_cast<const Ipv6Hdr*>(bytes.data()) : nullptr; }
    const TcpHdr* tcp() const { return tcp_ ? reinterpret_cast<const TcpHdr*>(bytes.data() + tcp_off_) : nullptr; }

    std::uint8_t*       payload() { return bytes.data() + payload_off_; }
    const std::uint8_t* payload() const { return bytes.data() + payload_off_; }

    std::size_t payload_len() const { return payload_len_; }
    std::size_t ip_hdr_len() const { return ip_hdr_len_; }
    std::size_t tcp_hdr_len() const { return tcp_hdr_len_; }

    void refresh_lengths_and_checksums();

private:
    bool        ipv4_ = false;
    bool        ipv6_ = false;
    bool        tcp_ = false;
    std::size_t ip_hdr_len_ = 0;
    std::size_t tcp_off_ = 0;
    std::size_t tcp_hdr_len_ = 0;
    std::size_t payload_off_ = 0;
    std::size_t payload_len_ = 0;
};

}
