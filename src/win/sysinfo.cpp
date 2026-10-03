#include "win/sysinfo.hpp"

#include <windows.h>

#include <cstdio>
#include <cstring>

#include "zc/log.hpp"

namespace zc::win {
namespace {

BOOL WINAPI console_handler(DWORD type) {
    switch (type) {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:
        // Ask the capture loop to finish; the loop exits and closes the handle.
        zc::log::request_stop();
        return TRUE;
    default:
        return FALSE;
    }
}

std::string trim_zw(const std::wstring& text) {
    std::size_t begin = 0;
    while (begin < text.size() && (text[begin] == L' ' || text[begin] == L'\0')) ++begin;
    std::size_t end = text.size();
    while (end > begin && (text[end - 1] == L' ' || text[end - 1] == L'\0')) --end;
    return std::string(text.begin() + static_cast<std::ptrdiff_t>(begin),
                       text.begin() + static_cast<std::ptrdiff_t>(end));
}

}  // namespace

bool is_elevated() {
    // CheckTokenMembership with a null token uses the effective token of the thread, which
    // correctly reports the UAC-elevated state for this process.
    SID_IDENTIFIER_AUTHORITY nt_authority = SECURITY_NT_AUTHORITY;
    PSID administrators = nullptr;
    if (!AllocateAndInitializeSid(&nt_authority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                  DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &administrators)) {
        return false;
    }
    BOOL member = FALSE;
    const BOOL ok = CheckTokenMembership(nullptr, administrators, &member);
    FreeSid(administrators);
    return ok != FALSE && member != FALSE;
}

std::string os_version() {
    // RtlGetVersion is the only API that reports the real version on modern Windows;
    // GetVersionEx is shimmed for compatibility.
    using RtlGetVersionFn = LONG(WINAPI*)(PRTL_OSVERSIONINFOW);
    const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll != nullptr) {
        const auto fn = reinterpret_cast<RtlGetVersionFn>(
            reinterpret_cast<void*>(GetProcAddress(ntdll, "RtlGetVersion")));
        if (fn != nullptr) {
            RTL_OSVERSIONINFOW info{};
            info.dwOSVersionInfoSize = sizeof(info);
            if (fn(&info) == 0) {
                return std::to_string(info.dwMajorVersion) + "." +
                       std::to_string(info.dwMinorVersion) + "." +
                       std::to_string(info.dwBuildNumber);
            }
        }
    }
    return "unknown";
}

std::string process_architecture() {
    // GetNativeSystemInfo reports the real architecture, not the emulated one.
    SYSTEM_INFO info{};
    GetNativeSystemInfo(&info);
    switch (info.wProcessorArchitecture) {
    case PROCESSOR_ARCHITECTURE_AMD64: return "x64";
    case PROCESSOR_ARCHITECTURE_ARM64: return "arm64";
    case PROCESSOR_ARCHITECTURE_INTEL: return "x86";
    default: return "unknown";
    }
}

bool os_is_64bit() {
    SYSTEM_INFO info{};
    GetNativeSystemInfo(&info);
    return info.wProcessorArchitecture != PROCESSOR_ARCHITECTURE_INTEL;
}

void install_console_handler() { SetConsoleCtrlHandler(console_handler, TRUE); }

bool has_console() {
    const HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    return out != nullptr && out != INVALID_HANDLE_VALUE && GetConsoleMode(out, nullptr) != 0;
}

}  // namespace zc::win
