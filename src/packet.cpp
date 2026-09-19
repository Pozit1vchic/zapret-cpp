#include "packet.hpp"

#include "csum.hpp"

namespace zc {

static std::uint16_t bswap16(std::uint16_t v) {
    return static_cast<std::uint16_t>((v >> 8) | (v << 8));
}

bool Packet::parse() {
    ipv4_ = ipv6_ = tcp_ = false;
    ip_hdr_len_ = tcp_off_ = tcp_hdr_len_ = payload_off_ = payload_len_ = 0;

    if (bytes.size() < 20) {
        return false;
    }

    std::uint8_t version = static_cast<std::uint8_t>(bytes[0] >> 4);
    std::size_t  l4_off = 0;

    if (version == 4) {
        ipv4_ = true;
        IpHdr* h = reinterpret_cast<IpHdr*>(bytes.data());
        ip_hdr_len_ = static_cast<std::size_t>(h->ver_ihl & 0x0f) * 4;
        if (ip_hdr_len_ < 20 || bytes.size() < ip_hdr_len_) {
            return false;
        }
        if (h->proto != IPPROTO_TCP_NUM) {
            return false;
        }
        l4_off = ip_hdr_len_;
    } else if (version == 6) {
        ipv6_ = true;
        ip_hdr_len_ = 40;
        if (bytes.size() < 40) {
            return false;
        }
        Ipv6Hdr* h = reinterpret_cast<Ipv6Hdr*>(bytes.data());
        if (h->next_header != IPPROTO_TCP_NUM) {
            return false;
        }
        l4_off = 40;
    } else {
        return false;
    }

    if (bytes.size() < l4_off + 20) {
        return false;
    }

    TcpHdr* t = reinterpret_cast<TcpHdr*>(bytes.data() + l4_off);
    tcp_hdr_len_ = static_cast<std::size_t>((t->data_off >> 4) & 0x0f) * 4;
    if (tcp_hdr_len_ < 20 || bytes.size() < l4_off + tcp_hdr_len_) {
        return false;
    }

    tcp_ = true;
    tcp_off_ = l4_off;
    payload_off_ = l4_off + tcp_hdr_len_;
    payload_len_ = bytes.size() - payload_off_;
    return true;
}

void Packet::refresh_lengths_and_checksums() {
    if (!tcp_) {
        return;
    }
    TcpHdr* t = tcp();

    if (ipv4_) {
        IpHdr* h = ip();
        h->total_len = bswap16(static_cast<std::uint16_t>(bytes.size()));
        h->checksum = 0;
        h->checksum = bswap16(checksum16(bytes.data(), ip_hdr_len_));

        t->checksum = 0;
        std::uint32_t sum = sum_bytes(bytes.data() + 12, 8, 0);
        sum += IPPROTO_TCP_NUM;
        sum += static_cast<std::uint16_t>(bytes.size() - ip_hdr_len_);
        sum = sum_bytes(bytes.data() + tcp_off_, bytes.size() - tcp_off_, sum);
        t->checksum = bswap16(fold_sum(sum));
    } else if (ipv6_) {
        Ipv6Hdr* h = ip6();
        h->payload_len = bswap16(static_cast<std::uint16_t>(bytes.size() - 40));

        t->checksum = 0;
        std::uint32_t sum = 0;
        sum = sum_bytes(h->src, 16, sum);
        sum = sum_bytes(h->dst, 16, sum);
        sum += IPPROTO_TCP_NUM;
        sum += static_cast<std::uint16_t>(bytes.size() - 40);
        sum = sum_bytes(bytes.data() + tcp_off_, bytes.size() - tcp_off_, sum);
        t->checksum = bswap16(fold_sum(sum));
    }
}

}
