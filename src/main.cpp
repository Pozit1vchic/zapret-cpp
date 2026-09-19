#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include <windows.h>
#include <windivert.h>

#include "desync.hpp"
#include "packet.hpp"
#include "services.hpp"
#include "tls.hpp"

namespace {

volatile LONG g_stop = 0;

BOOL WINAPI on_ctrl(DWORD type) {
    (void)type;
    InterlockedExchange(&g_stop, 1);
    return TRUE;
}

void print_usage(const char* exe) {
    std::printf(
        "usage: %s [options]\n"
        "  --strategy=split|disorder|multidisorder|fake|fake-multidisorder|fake-auto\n"
        "                                   default: fake-multidisorder (auto per-service)\n"
        "  --split=N                        segment offset, -1 = auto (SNI middle)\n"
        "  --ttl=N                          fake packet TTL, default: 4\n"
        "  --fake-sni=HOST                  decoy SNI for fake strategies\n"
        "  --repeats=N                      send desync packets N times, default: 1\n"
        "  --segs=N                         multidisorder segment count (2..8), default: 4\n"
        "  --badseq                         use bogus TCP seq on the trick segment (fooling)\n"
        "  --fake-rnd                       randomize fake TLS payload bytes\n"
        "  --all                            bypass every TLS host (disable whitelist)\n"
        "  --no-auto                        use --strategy for all hosts, ignore per-service\n"
        "  --list                           print tracked service list and exit\n"
        "  --filter=\"...\"                  WinDivert filter override\n",
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

}

int main(int argc, char** argv) {
    zc::Config  cfg;
    std::string filter = "outbound and tcp and (tcp.DstPort == 443 or tcp.DstPort == 80)";

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
        } else if (key == "--all") {
            cfg.only_listed = false;
        } else if (key == "--no-auto") {
            cfg.auto_strategy = false;
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

    HANDLE wd = WinDivertOpen(filter.c_str(), WINDIVERT_LAYER_NETWORK, 0, 0);
    if (wd == INVALID_HANDLE_VALUE) {
        std::fprintf(stderr,
                     "WinDivertOpen failed (error %lu). Run as Administrator and place "
                     "WinDivert.dll / WinDivert64.sys next to the exe.\n",
                     GetLastError());
        return 1;
    }

    SetConsoleCtrlHandler(on_ctrl, TRUE);

    std::printf("[zc] filter   : %s\n", filter.c_str());
    std::printf("[zc] strategy : %s%s\n", strategy_name(cfg.strategy),
                cfg.auto_strategy ? " (auto per-service)" : "");
    std::printf("[zc] scope    : %s\n",
                cfg.only_listed ? "tracked services only" : "ALL TLS hosts");
    std::printf("[zc] list     : %zu services (--list for details)\n", zc::services().size());

    std::vector<unsigned char> buffer(WINDIVERT_MTU_MAX);

    while (InterlockedCompareExchange(&g_stop, 0, 0) == 0) {
        WINDIVERT_ADDRESS addr;
        UINT              len = 0;

        if (!WinDivertRecv(wd, buffer.data(), static_cast<UINT>(buffer.size()), &len, &addr)) {
            std::fprintf(stderr, "WinDivertRecv failed: %lu\n", GetLastError());
            continue;
        }

        zc::Packet pkt;
        pkt.bytes.assign(buffer.begin(), buffer.begin() + len);
        pkt.addr.outbound = addr.Outbound != 0;

        bool handled = false;

        if (addr.Outbound && pkt.parse() && pkt.is_tcp()) {
            zc::TlsClientHello tls = zc::parse_client_hello(pkt.payload(), pkt.payload_len());
            if (tls.valid) {
                std::string sni = zc::client_hello_sni(pkt.payload(), pkt.payload_len(), tls);
                const zc::Service* svc = zc::find_service(sni);

                bool want = cfg.only_listed ? (svc != nullptr) : true;

                if (want) {
                    zc::Config use = cfg;
                    if (cfg.auto_strategy && svc != nullptr) {
                        zc::apply_service(*svc, use);
                    }

                    std::vector<zc::Packet> out = zc::apply_desync(pkt, tls, use);
                    for (zc::Packet& o : out) {
                        WINDIVERT_ADDRESS a = addr;
                        if (!WinDivertSend(wd, o.bytes.data(), static_cast<UINT>(o.bytes.size()),
                                           nullptr, &a)) {
                            std::fprintf(stderr, "WinDivertSend failed: %lu\n", GetLastError());
                        }
                    }
                    handled = true;

                    std::printf("[zc] %-40s -> %s [%s x%d]\n", sni.c_str(),
                                svc ? svc->name : "default",
                                strategy_name(use.strategy), use.repeats);
                }
            }
        }

        if (!handled) {
            if (!WinDivertSend(wd, buffer.data(), len, nullptr, &addr)) {
                std::fprintf(stderr, "WinDivertSend failed: %lu\n", GetLastError());
            }
        }
    }

    WinDivertClose(wd);
    std::printf("[zc] stopped\n");
    return 0;
}
