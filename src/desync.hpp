#pragma once

#include <string>
#include <vector>

#include "packet.hpp"
#include "tls.hpp"

namespace zc {

enum class Strategy {
    Split,
    Disorder,
    Multidisorder,
    FakeTtl,
    FakeMultidisorder,
    FakeAuto,
};

struct Config {
    Strategy    strategy = Strategy::FakeMultidisorder;
    int         split_pos = -1;
    int         fake_ttl = 4;
    std::string fake_sni = "www.google.com";
    bool        auto_strategy = true;
    bool        only_listed = true;

    int  repeats = 1;
    bool fooling_badseq = false;
    bool fake_mod_rnd = false;
    bool fake_mod_dupsid = false;
    bool fake_mod_sni = true;
    int  disorder_segments = 4;
};

std::vector<Packet> apply_desync(const Packet& pkt, const TlsClientHello& tls, const Config& cfg);

}
