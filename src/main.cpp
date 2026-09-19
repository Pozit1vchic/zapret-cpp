#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include <windows.h>
#include <windivert.h>

#include "desync.hpp"
#include "packet.hpp"
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
        "  --strategy=split|disorder|fake   default: split\n"
        "  --split=N                        segment offset, -1 = auto (SNI middle)\n"
        "  --ttl=N                          fake packet TTL, default: 4\n"
        "  --fake-sni=HOST                  decoy SNI for fake strategy\n"
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
    case zc::Strategy::Split:    return "split";
    case zc::Strategy::Disorder: return "disorder";
    case zc::Strategy::FakeTtl:  return "fake";
    }
    return "?";
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
        } else if (key == "--strategy") {
            if (val == "split") {
                cfg.strategy = zc::Strategy::Split;
            } else if (val == "disorder") {
                cfg.strategy = zc::Strategy::Disorder;
            } else if (val == "fake") {
                cfg.strategy = zc::Strategy::FakeTtl;
            } else {
                std::fprintf(stderr, "unknown strategy: %s\n", val.c_str());
                return 2;
            }
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
    std::printf("[zc] strategy : %s\n", strategy_name(cfg.strategy));

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
        pkt.addr = addr;

        bool handled = false;

        if (addr.Outbound && pkt.parse() && pkt.is_tcp()) {
            zc::TlsClientHello tls = zc::parse_client_hello(pkt.payload(), pkt.payload_len());
            if (tls.valid) {
                std::vector<zc::Packet> out = zc::apply_desync(pkt, tls, cfg);
                for (zc::Packet& o : out) {
                    WINDIVERT_ADDRESS a = o.addr;
                    if (!WinDivertSend(wd, o.bytes.data(), static_cast<UINT>(o.bytes.size()),
                                       nullptr, &a)) {
                        std::fprintf(stderr, "WinDivertSend failed: %lu\n", GetLastError());
                    }
                }
                handled = true;
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
