#include "windivert_dyn.hpp"

#include <windows.h>
#include <windivert.h>

#include <cstdio>

namespace {

typedef HANDLE(WINAPI* fn_Open)(LPCSTR, WINDIVERT_LAYER, UINT16, UINT64);
typedef BOOL(WINAPI* fn_Close)(HANDLE);
typedef BOOL(WINAPI* fn_Recv)(HANDLE, PVOID, UINT, UINT*, PWINDIVERT_ADDRESS);
typedef BOOL(WINAPI* fn_Send)(HANDLE, PVOID, UINT, UINT*, PWINDIVERT_ADDRESS);
typedef BOOL(WINAPI* fn_GetLastError)(HANDLE);

struct WdApi {
    fn_Open   open = nullptr;
    fn_Close  close = nullptr;
    fn_Recv   recv = nullptr;
    fn_Send   send = nullptr;
    fn_GetLastError last_error = nullptr;
};

HMODULE g_module = nullptr;
WdApi*  g_api = nullptr;

WdApi* load_api() {
    if (g_api != nullptr) {
        return g_api;
    }
    if (g_module == nullptr) {
        g_module = LoadLibraryW(L"WinDivert.dll");
        if (g_module == nullptr) {
            return nullptr;
        }
    }

    static WdApi api;
    api.open       = (fn_Open)GetProcAddress(g_module, "WinDivertOpen");
    api.close      = (fn_Close)GetProcAddress(g_module, "WinDivertClose");
    api.recv       = (fn_Recv)GetProcAddress(g_module, "WinDivertRecv");
    api.send       = (fn_Send)GetProcAddress(g_module, "WinDivertSend");
    api.last_error = (fn_GetLastError)GetProcAddress(g_module, "WinDivertGetLastError");

    if (!api.open || !api.close || !api.recv || !api.send) {
        g_api = nullptr;
        return nullptr;
    }
    g_api = &api;
    return g_api;
}

}

namespace zc {

Windivert::~Windivert() {
    close();
}

bool Windivert::open(const std::string& filter) {
    WdApi* api = load_api();
    if (api == nullptr) {
        last_error_ = ::GetLastError();
        return false;
    }
    handle_ = api->open(filter.c_str(), WINDIVERT_LAYER_NETWORK, 0, 0);
    if (handle_ == nullptr) {
        last_error_ = ::GetLastError();
        return false;
    }
    return true;
}

void Windivert::close() {
    if (handle_ != nullptr && g_api != nullptr) {
        g_api->close(handle_);
        handle_ = nullptr;
    }
    if (g_module != nullptr) {
        FreeLibrary(g_module);
        g_module = nullptr;
        g_api = nullptr;
    }
}

bool Windivert::receive(unsigned char* buffer, unsigned int capacity, unsigned int& length,
                        WdAddress& addr) {
    WdApi* api = load_api();
    if (api == nullptr || handle_ == nullptr) {
        return false;
    }
    WINDIVERT_ADDRESS waddr{};
    UINT  out = 0;
    if (!api->recv(handle_, buffer, capacity, &out, &waddr)) {
        last_error_ = api->last_error(handle_);
        return false;
    }
    length = out;
    addr.outbound = waddr.Outbound != 0;
    addr.loopback = waddr.Loopback != 0;
    return true;
}

bool Windivert::send(const unsigned char* buffer, unsigned int length, const WdAddress& addr) {
    WdApi* api = load_api();
    if (api == nullptr || handle_ == nullptr) {
        return false;
    }
    WINDIVERT_ADDRESS waddr{};
    waddr.Outbound = addr.outbound ? 1 : 0;
    waddr.Loopback = addr.loopback ? 1 : 0;
    BOOL ok = api->send(handle_, const_cast<unsigned char*>(buffer), length, nullptr, &waddr);
    if (!ok) {
        last_error_ = api->last_error(handle_);
    }
    return ok != FALSE;
}

std::string Windivert::last_open_error() {
    DWORD err = ::GetLastError();
    if (err == ERROR_MOD_NOT_FOUND) {
        return "WinDivert.dll not found. Place it next to the exe.";
    }
    if (err == ERROR_PROC_NOT_FOUND) {
        return "WinDivert.dll is too old or corrupt.";
    }
    if (err == 0) {
        return "WinDivertOpen failed (no detail). Run as Administrator.";
    }
    char buf[128] = {};
    snprintf(buf, sizeof(buf), "WinDivertOpen failed (error %lu). Run as Administrator.", err);
    return buf;
}

}
