#include "packet.hpp"

#include "csum.hpp"

namespace zc {

static std::uint16_t bswap16(std::uint16_t v) {
    return static_cast<std::uint16_t>((v >> 8) | (v << 8));
}

bool Packet::parse() {
    ipv4_ = ipv6_ = tcp_ = udp_ = false;
    ip_hdr_len_ = l4_off_ = tcp_off_ = tcp_hdr_len_ = payload_off_ = payload_len_ = 0;

    if (bytes.size() < 20) {
        return false;
    }

    std::uint8_t version = static_cast<std::uint8_t>(bytes[0] >> 4);
    std::uint8_t proto = 0;

    if (version == 4) {
        ipv4_ = true;
        IpHdr* h = reinterpret_cast<IpHdr*>(bytes.data());
        ip_hdr_len_ = static_cast<std::size_t>(h->ver_ihl & 0x0f) * 4;
        if (ip_hdr_len_ < 20 || bytes.size() < ip_hdr_len_) {
            return false;
        }
        std::uint16_t frag = (static_cast<std::uint16_t>(h->frag_off >> 8) |
                              static_cast<std::uint16_t>(h->frag_off << 8));
        if ((frag & 0x1fff) != 0) {
            return false;
        }
        proto = h->proto;
        l4_off_ = ip_hdr_len_;
    } else if (version == 6) {
        ipv6_ = true;
        ip_hdr_len_ = 40;
        if (bytes.size() < 40) {
            return false;
        }
        Ipv6Hdr* h = reinterpret_cast<Ipv6Hdr*>(bytes.data());
        proto = h->next_header;
        l4_off_ = 40;
    } else {
        return false;
    }

    if (proto == IPPROTO_TCP_NUM) {
        if (bytes.size() < l4_off_ + 20) {
            return false;
        }
        TcpHdr* t = reinterpret_cast<TcpHdr*>(bytes.data() + l4_off_);
        tcp_hdr_len_ = static_cast<std::size_t>((t->data_off >> 4) & 0x0f) * 4;
        if (tcp_hdr_len_ < 20 || bytes.size() < l4_off_ + tcp_hdr_len_) {
            return false;
        }
        tcp_ = true;
        tcp_off_ = l4_off_;
        payload_off_ = l4_off_ + tcp_hdr_len_;
        payload_len_ = bytes.size() - payload_off_;
        return true;
    }

    if (proto == IPPROTO_UDP_NUM) {
        if (bytes.size() < l4_off_ + 8) {
            return false;
        }
        udp_ = true;
        payload_off_ = l4_off_ + 8;
        payload_len_ = bytes.size() - payload_off_;
        return true;
    }

    return false;
}

void Packet::refresh_lengths_and_checksums() {
    std::uint8_t proto = tcp_ ? IPPROTO_TCP_NUM : (udp_ ? IPPROTO_UDP_NUM : 0);
    if (proto == 0) {
        return;
    }

    if (ipv4_) {
        IpHdr* h = ip();
        h->total_len = bswap16(static_cast<std::uint16_t>(bytes.size()));
        h->checksum = 0;
        h->checksum = bswap16(checksum16(bytes.data(), ip_hdr_len_));

        if (udp_) {
            udp()->checksum = 0;
            udp()->length = bswap16(static_cast<std::uint16_t>(bytes.size() - ip_hdr_len_));
        } else {
            tcp()->checksum = 0;
        }

        std::uint32_t sum = sum_bytes(bytes.data() + 12, 8, 0);
        sum += proto;
        sum += static_cast<std::uint16_t>(bytes.size() - ip_hdr_len_);
        sum = sum_bytes(bytes.data() + l4_off_, bytes.size() - l4_off_, sum);
        std::uint16_t cs = bswap16(fold_sum(sum));
        if (udp_) {
            udp()->checksum = (cs == 0) ? 0xffff : cs;
        } else {
            tcp()->checksum = cs;
        }
    } else if (ipv6_) {
        Ipv6Hdr* h = ip6();
        h->payload_len = bswap16(static_cast<std::uint16_t>(bytes.size() - 40));

        if (udp_) {
            udp()->checksum = 0;
            udp()->length = bswap16(static_cast<std::uint16_t>(bytes.size() - 40));
        } else {
            tcp()->checksum = 0;
        }

        std::uint32_t sum = 0;
        sum = sum_bytes(h->src, 16, sum);
        sum = sum_bytes(h->dst, 16, sum);
        sum += proto;
        sum += static_cast<std::uint16_t>(bytes.size() - 40);
        sum = sum_bytes(bytes.data() + l4_off_, bytes.size() - l4_off_, sum);
        std::uint16_t cs = bswap16(fold_sum(sum));
        if (udp_) {
            udp()->checksum = (cs == 0) ? 0xffff : cs;
        } else {
            tcp()->checksum = cs;
        }
    }
}

}
