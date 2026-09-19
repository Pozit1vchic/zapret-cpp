#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include <windows.h>

#include "desync.hpp"
#include "http.hpp"
#include "packet.hpp"
#include "quic.hpp"
#include "services.hpp"
#include "tls.hpp"
#include "windivert_dyn.hpp"

constexpr unsigned int MTU_MAX = 65536;

namespace {

volatile LONG g_stop = 0;

BOOL WINAPI on_ctrl(DWORD type) {
    (void)type;
    InterlockedExchange(&g_stop, 1);
    return TRUE;
}

void pause_before_exit() {
    HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
    if (h == nullptr || h == INVALID_HANDLE_VALUE) {
        return;
    }
    DWORD mode = 0;
    if (!GetConsoleMode(h, &mode)) {
        return;
    }
    std::fprintf(stderr, "[zc] press Enter to exit...");
    std::fflush(stderr);
    char line[8];
    std::fgets(line, sizeof(line), stdin);
}

void print_usage(const char* exe) {
    std::printf(
        "zapret-cpp - universal DPI bypass (TCP+TLS, HTTP, QUIC)\n"
        "usage: %s [options]\n"
        "  --strategy=split|disorder|multidisorder|fake|fake-multidisorder|fake-auto\n"
        "                                   force one strategy for all hosts\n"
        "  --split=N                        segment offset, -1 = auto (SNI middle)\n"
        "  --ttl=N                          fake packet TTL, default: 4\n"
        "  --fake-sni=HOST                  decoy SNI for fake strategies\n"
        "  --repeats=N                      send desync packets N times, default: 1\n"
        "  --segs=N                         multidisorder segment count (2..8), default: 4\n"
        "  --badseq                         use bogus TCP seq on the trick segment (fooling)\n"
        "  --fake-rnd                       randomize fake TLS payload bytes\n"
        "  --listed                         only bypass known services (default: ALL traffic)\n"
        "  --no-quic                        disable UDP/QUIC (HTTP/3) handling\n"
        "  --no-http                        disable plain HTTP (port 80) handling\n"
        "  --udplen=N                       pad (N>0) or trim (N<0) UDP payload bytes\n"
        "  --no-fake-quic                   disable fake QUIC Initial injection\n"
        "  --list                           print tracked service list and exit\n"
        "  --filter=\"...\"                  WinDivert filter override\n"
        "  --help                           this help\n"
        "\n"
        "Default: bypass EVERYTHING. Known services get tuned per-service strategies,\n"
        "unknown hosts fall back to the built-in universal strategy.\n",
        exe);
}

bool parse_int(const char* s, int& out) {
    char* end = nullptr;
    long  v = std::strtol(s, &end, 10);
    if (end == s || *end != '\0') {
        return false;
    }
    out = static_cast<int>(v);
    return true;
}

const char* strategy_name(zc::Strategy s) {
    switch (s) {
    case zc::Strategy::Split:             return "split";
    case zc::Strategy::Disorder:          return "disorder";
    case zc::Strategy::Multidisorder:     return "multidisorder";
    case zc::Strategy::FakeTtl:           return "fake";
    case zc::Strategy::FakeMultidisorder: return "fake-multidisorder";
    case zc::Strategy::FakeAuto:          return "fake-auto";
    case zc::Strategy::FakeQuic:          return "fake-quic";
    case zc::Strategy::HttpSplit:         return "http-split";
    case zc::Strategy::HttpDisorder:      return "http-disorder";
    }
    return "?";
}

bool parse_strategy(const std::string& val, zc::Strategy& out) {
    if (val == "split") {
        out = zc::Strategy::Split;
    } else if (val == "disorder") {
        out = zc::Strategy::Disorder;
    } else if (val == "multidisorder") {
        out = zc::Strategy::Multidisorder;
    } else if (val == "fake") {
        out = zc::Strategy::FakeTtl;
    } else if (val == "fake-multidisorder") {
        out = zc::Strategy::FakeMultidisorder;
    } else if (val == "fake-auto") {
        out = zc::Strategy::FakeAuto;
    } else {
        return false;
    }
    return true;
}

void print_services() {
    std::printf("tracked services (%zu):\n", zc::services().size());
    for (const zc::Service& s : zc::services()) {
        std::printf("  %-16s %-18s reps=%d badseq=%d ", s.name, strategy_name(s.strategy),
                    s.repeats, s.fooling_badseq ? 1 : 0);
        for (const char* suf : s.suffixes) {
            if (suf == nullptr) {
                break;
            }
            std::printf(" %s", suf);
        }
        std::printf("\n");
    }
}

void send_all(zc::Windivert& wd, const std::vector<zc::Packet>& out, const zc::WdAddress& addr) {
    for (const zc::Packet& o : out) {
        if (!wd.send(o.bytes.data(), static_cast<unsigned int>(o.bytes.size()), addr)) {
            std::fprintf(stderr, "WinDivertSend failed (%lu)\n", wd.last_error());
        }
    }
}

}

int main(int argc, char** argv) {
    zc::Config  cfg;
    cfg.only_listed = false;
    cfg.auto_strategy = true;

    bool enable_quic = true;
    bool enable_http = true;

    std::string filter =
        "outbound and ((tcp.DstPort == 443 or tcp.DstPort == 80 or tcp.DstPort == 8443) "
        "or (udp.DstPort == 443))";

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        std::size_t eq = a.find('=');
        std::string key = (eq == std::string::npos) ? a : a.substr(0, eq);
        std::string val = (eq == std::string::npos) ? std::string() : a.substr(eq + 1);

        if (key == "--help" || key == "-h") {
            print_usage(argv[0]);
            return 0;
        } else if (key == "--list") {
            print_services();
            return 0;
        } else if (key == "--listed") {
            cfg.only_listed = true;
        } else if (key == "--no-quic") {
            enable_quic = false;
        } else if (key == "--no-http") {
            enable_http = false;
        } else if (key == "--no-fake-quic") {
            cfg.fake_quic = false;
        } else if (key == "--udplen") {
            if (!parse_int(val.c_str(), cfg.udplen_increment)) {
                std::fprintf(stderr, "bad --udplen value\n");
                return 2;
            }
        } else if (key == "--strategy") {
            if (!parse_strategy(val, cfg.strategy)) {
                std::fprintf(stderr, "unknown strategy: %s\n", val.c_str());
                return 2;
            }
            cfg.auto_strategy = false;
        } else if (key == "--split") {
            if (!parse_int(val.c_str(), cfg.split_pos)) {
                std::fprintf(stderr, "bad --split value\n");
                return 2;
            }
        } else if (key == "--ttl") {
            if (!parse_int(val.c_str(), cfg.fake_ttl)) {
                std::fprintf(stderr, "bad --ttl value\n");
                return 2;
            }
        } else if (key == "--repeats") {
            if (!parse_int(val.c_str(), cfg.repeats) || cfg.repeats < 1) {
                std::fprintf(stderr, "bad --repeats value\n");
                return 2;
            }
        } else if (key == "--segs") {
            if (!parse_int(val.c_str(), cfg.disorder_segments) || cfg.disorder_segments < 2 ||
                cfg.disorder_segments > 8) {
                std::fprintf(stderr, "bad --segs value (2..8)\n");
                return 2;
            }
        } else if (key == "--badseq") {
            cfg.fooling_badseq = true;
        } else if (key == "--fake-rnd") {
            cfg.fake_mod_rnd = true;
        } else if (key == "--fake-sni") {
            cfg.fake_sni = val;
        } else if (key == "--filter") {
            filter = val;
        } else {
            std::fprintf(stderr, "unknown option: %s\n", key.c_str());
            print_usage(argv[0]);
            return 2;
        }
    }

    zc::Windivert wd;
    if (!wd.open(filter)) {
        std::fprintf(stderr, "\n[zc] ERROR: %s\n", zc::Windivert::last_open_error().c_str());
        std::fprintf(stderr, "[zc] Make sure WinDivert.dll and WinDivert64.sys are next to the exe,\n");
        std::fprintf(stderr, "[zc] and that you are running as Administrator.\n\n");
        pause_before_exit();
        return 1;
    }

    SetConsoleCtrlHandler(on_ctrl, TRUE);

    std::printf("[zc] zapret-cpp universal\n");
    std::printf("[zc] filter : %s\n", filter.c_str());
    std::printf("[zc] scope  : %s\n",
                cfg.only_listed ? "tracked services only" : "ALL traffic");
    std::printf("[zc] modes  : TLS%s%s\n", enable_http ? " + HTTP" : "",
                enable_quic ? " + QUIC" : "");
    if (cfg.udplen_increment != 0) {
        std::printf("[zc] udplen : %+d bytes\n", cfg.udplen_increment);
    }
    std::printf("[zc] fallback strategy: %s\n", strategy_name(cfg.strategy));

    std::vector<unsigned char> buffer(MTU_MAX);

    while (InterlockedCompareExchange(&g_stop, 0, 0) == 0) {
        zc::WdAddress addr;
        unsigned int  len = 0;

        if (!wd.receive(buffer.data(), static_cast<unsigned int>(buffer.size()), len, addr)) {
            std::fprintf(stderr, "WinDivertRecv failed (%lu)\n", wd.last_error());
            continue;
        }

        zc::Packet pkt;
        pkt.bytes.assign(buffer.begin(), buffer.begin() + len);
        pkt.addr.outbound = addr.outbound;

        bool handled = false;

        if (addr.outbound && pkt.parse()) {
            if (pkt.is_tcp()) {
                zc::TlsClientHello tls = zc::parse_client_hello(pkt.payload(), pkt.payload_len());
                if (tls.valid) {
                    std::string sni = zc::client_hello_sni(pkt.payload(), pkt.payload_len(), tls);
                    const zc::Service* svc = zc::find_service(sni);
                    if (!cfg.only_listed || svc != nullptr) {
                        zc::Config use = cfg;
                        if (cfg.auto_strategy && svc != nullptr) {
                            zc::apply_service(*svc, use);
                        }
                        std::vector<zc::Packet> out = zc::apply_desync(pkt, tls, use);
                        send_all(wd, out, addr);
                        handled = true;
                        std::printf("[zc] TLS  %-42s -> %s [%s x%d]\n", sni.c_str(),
                                    svc ? svc->name : "default", strategy_name(use.strategy),
                                    use.repeats);
                    }
                } else if (enable_http) {
                    zc::HttpRequest http =
                        zc::parse_http_request(pkt.payload(), pkt.payload_len());
                    if (http.valid) {
                        const zc::Service* svc = zc::find_service(http.host);
                        if (!cfg.only_listed || svc != nullptr) {
                            zc::Config use = cfg;
                            if (cfg.auto_strategy && svc != nullptr) {
                                zc::apply_service(*svc, use);
                            }
                            std::size_t hs = http.host_value_offset + http.host_value_length / 2;
                            std::vector<zc::Packet> out = zc::apply_http_desync(pkt, use, hs);
                            send_all(wd, out, addr);
                            handled = true;
                            std::printf("[zc] HTTP %-42s -> %s\n", http.host.c_str(),
                                        svc ? svc->name : "default");
                        }
                    }
                }
            } else if (pkt.is_udp() && enable_quic) {
                zc::UdpHdr* u = pkt.udp();
                if (u != nullptr) {
                    unsigned dst_port = static_cast<unsigned>((u->dst_port << 8) |
                                                              (u->dst_port >> 8)) & 0xffff;
                    if (dst_port == 443) {
                        zc::QuicInitial quic =
                            zc::parse_quic_initial(pkt.payload(), pkt.payload_len());
                        if (quic.valid) {
                            std::vector<zc::Packet> out = zc::apply_quic_desync(pkt, quic, cfg);
                            send_all(wd, out, addr);
                            handled = true;
                            std::printf("[zc] QUIC udp/443 initial (dcid=%zu) -> %s\n",
                                        quic.dcid_length,
                                        cfg.fake_quic ? "fake+real" : "real");
                        }
                    }
                }
            }
        }

        if (!handled) {
            if (!wd.send(buffer.data(), len, addr)) {
                std::fprintf(stderr, "WinDivertSend failed (%lu)\n", wd.last_error());
            }
        }
    }

    wd.close();
    std::printf("[zc] stopped\n");
    return 0;
}
