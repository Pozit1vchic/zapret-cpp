#pragma once

#include <string>
#include <vector>

#include "packet.hpp"
#include "tls.hpp"

namespace zc {

enum class Strategy {
    Split,
    Disorder,
    FakeTtl,
};

struct Config {
    Strategy    strategy = Strategy::Split;
    int         split_pos = -1;
    int         fake_ttl = 4;
    std::string fake_sni = "www.microsoft.com";
};

std::vector<Packet> apply_desync(const Packet& pkt, const TlsClientHello& tls, const Config& cfg);

}
