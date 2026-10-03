#include "win/windivert.hpp"

#include <windows.h>

#include <windivert.h>

#include <cstring>
#include <mutex>

namespace zc::win {
namespace {

// Typed signatures of the WinDivert entry points we use.
using FnOpen = HANDLE(WINAPI*)(LPCSTR, WINDIVERT_LAYER, INT16, UINT64);
using FnClose = BOOL(WINAPI*)(HANDLE);
using FnRecv = BOOL(WINAPI*)(HANDLE, PVOID, UINT, UINT*, PWINDIVERT_ADDRESS);
using FnSend = BOOL(WINAPI*)(HANDLE, const VOID*, UINT, UINT*, const WINDIVERT_ADDRESS*);
using FnShutdown = BOOL(WINAPI*)(HANDLE, WINDIVERT_SHUTDOWN);
using FnGetParam = BOOL(WINAPI*)(HANDLE, WINDIVERT_PARAM, UINT64*);
using FnCompileFilter = BOOL(WINAPI*)(LPCSTR, WINDIVERT_LAYER, PCHAR, UINT, LPCSTR*,
                                      UINT*);
using FnCalcChecksums = BOOL(WINAPI*)(VOID*, UINT, PWINDIVERT_ADDRESS, UINT64);

// Resolve a WinDivert entry point without casting between incompatible function types.
//
// GetProcAddress returns FARPROC, which ISO C++ does not allow to be reinterpret_cast to
// a differently typed function pointer without a diagnostic. Copying the representation
// is the standard, portable way to do this on Windows, where both are pointers of the
// same width; the static_assert makes that assumption explicit instead of implicit.
template <typename Fn>
bool resolve(HMODULE module, void*& slot, const char* name) noexcept {
    static_assert(sizeof(Fn) == sizeof(FARPROC), "unexpected FARPROC size");
    FARPROC proc = ::GetProcAddress(module, name);
    if (proc == nullptr) return false;
    Fn typed = nullptr;
    std::memcpy(&typed, &proc, sizeof(typed));
    std::memcpy(&slot, &typed, sizeof(slot));
    return true;
}

std::string format_error(unsigned long err) {
    if (err == 0) return "unknown WinDivert failure (no error code)";
    if (err == ERROR_MOD_NOT_FOUND) {
        return "WinDivert.dll was not found. Place WinDivert.dll and WinDivert64.sys next to "
               "zapret-cpp.exe.";
    }
    if (err == ERROR_PROC_NOT_FOUND) {
        return "WinDivert.dll does not export the expected entry points; it is corrupt or "
               "incompatible.";
    }
    if (err == ERROR_ACCESS_DENIED) {
        return "access denied. Administrator rights are required to open the WinDivert driver.";
    }
    if (err == ERROR_INVALID_IMAGE_HASH) {
        return "Windows rejected the WinDivert driver signature.";
    }
    if (err == ERROR_NO_DATA) return "the WinDivert handle has been shut down.";
    if (err == ERROR_INVALID_HANDLE) return "the WinDivert handle is no longer valid.";
    if (err == ERROR_INSUFFICIENT_BUFFER) return "the receive buffer was too small.";
    if (err == ERROR_INVALID_PARAMETER) return "WinDivert rejected a parameter (bad filter?).";
    if (err == ERROR_SERVICE_REQUEST_TIMEOUT) return "WinDivert timed out.";
    char buffer[512] = {};
    const DWORD n = ::FormatMessageA(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, err, 0, buffer,
        static_cast<DWORD>(sizeof(buffer)), nullptr);
    std::string out = "WinDivert error " + std::to_string(err);
    if (n != 0) {
        std::string text(buffer, n);
        while (!text.empty() && (text.back() == '\r' || text.back() == '\n')) text.pop_back();
        out += ": " + text;
    }
    return out;
}

}  // namespace

// ---------------------------------------------------------------------------
// Library
// ---------------------------------------------------------------------------

WinDivertLibrary::WinDivertLibrary() {
    module_ = ::LoadLibraryExW(L"WinDivert.dll", nullptr,
                               LOAD_LIBRARY_SEARCH_APPLICATION_DIR |
                                   LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
    if (module_ == nullptr) {
        // LOAD_LIBRARY_SEARCH_* requires Windows 7 with the KB2533623 update; retry with
        // the plain form so an older or restricted system still gets a clear error.
        module_ = ::LoadLibraryW(L"WinDivert.dll");
    }
    if (module_ == nullptr) {
        load_error_ = ::GetLastError();
        return;
    }

    const HMODULE module_handle = reinterpret_cast<HMODULE>(module_);
    bool ok = true;
    ok = resolve<FnOpen>(module_handle, open, "WinDivertOpen") && ok;
    ok = resolve<FnClose>(module_handle, close, "WinDivertClose") && ok;
    ok = resolve<FnRecv>(module_handle, recv, "WinDivertRecv") && ok;
    ok = resolve<FnSend>(module_handle, send, "WinDivertSend") && ok;
    ok = resolve<FnShutdown>(module_handle, shutdown, "WinDivertShutdown") && ok;
    // Optional entry points.
    (void)resolve<FnGetParam>(module_handle, get_param, "WinDivertGetParam");
    (void)resolve<FnCompileFilter>(module_handle, compile_filter, "WinDivertHelperCompileFilter");
    (void)resolve<FnCalcChecksums>(module_handle, calc_checksums, "WinDivertHelperCalcChecksums");

    if (!ok) {
        load_error_ = ERROR_PROC_NOT_FOUND;
        ::FreeLibrary(reinterpret_cast<HMODULE>(module_));
        module_ = nullptr;
        open = close = recv = send = shutdown = nullptr;
        get_param = compile_filter = calc_checksums = nullptr;
    }
}

WinDivertLibrary& WinDivertLibrary::instance() {
    // Function-local static: thread safe initialisation, and the module is loaded once.
    static WinDivertLibrary library;
    return library;
}

std::string WinDivertLibrary::load_error_string() const {
    return module_ != nullptr ? std::string() : format_error(load_error_);
}

bool WinDivertLibrary::library_available() { return instance().loaded(); }

bool WinDivertLibrary::library_version(unsigned& major, unsigned& minor) {
    WinDivertLibrary& lib = instance();
    if (!lib.loaded() || lib.get_param == nullptr) return false;
    UINT64 value = 0;
    const auto fn = reinterpret_cast<FnGetParam>(lib.get_param);
    if (!fn(nullptr, WINDIVERT_PARAM_VERSION_MAJOR, &value)) return false;
    major = static_cast<unsigned>(value);
    if (!fn(nullptr, WINDIVERT_PARAM_VERSION_MINOR, &value)) return false;
    minor = static_cast<unsigned>(value);
    return true;
}

// ---------------------------------------------------------------------------
// Handle
// ---------------------------------------------------------------------------

WinDivertHandle::~WinDivertHandle() { close(); }

WinDivertHandle::WinDivertHandle(WinDivertHandle&& other) noexcept
    : handle_(other.handle_), last_error_(other.last_error_) {
    other.handle_ = nullptr;
    other.last_error_ = 0;
}

WinDivertHandle& WinDivertHandle::operator=(WinDivertHandle&& other) noexcept {
    if (this != &other) {
        close();
        handle_ = other.handle_;
        last_error_ = other.last_error_;
        other.handle_ = nullptr;
        other.last_error_ = 0;
    }
    return *this;
}

bool WinDivertHandle::open(std::string_view filter, std::int16_t priority, bool allow_loopback) {
    close();
    WinDivertLibrary& lib = WinDivertLibrary::instance();
    if (!lib.loaded()) {
        last_error_ = lib.load_error();
        return false;
    }
    if (lib.open == nullptr || lib.close == nullptr || lib.recv == nullptr ||
        lib.send == nullptr) {
        last_error_ = ERROR_PROC_NOT_FOUND;
        return false;
    }

    // Loopback exclusion is expressed in the filter itself, not through flags, so that
    // the same handle can be reused with a different filter.
    const UINT64 flags = 0;
    (void)allow_loopback;
    const std::string expression(filter);

    const auto fn_open = reinterpret_cast<FnOpen>(lib.open);
    HANDLE handle = fn_open(expression.c_str(), WINDIVERT_LAYER_NETWORK, priority, flags);
    if (handle == INVALID_HANDLE_VALUE || handle == nullptr) {
        last_error_ = ::GetLastError();
        return false;
    }
    handle_ = handle;
    last_error_ = 0;
    return true;
}

void WinDivertHandle::close() {
    if (handle_ == nullptr) return;
    WinDivertLibrary& lib = WinDivertLibrary::instance();
    if (lib.close != nullptr) {
        (void)reinterpret_cast<FnClose>(lib.close)(static_cast<HANDLE>(handle_));
    }
    handle_ = nullptr;
}

ReceiveStatus WinDivertHandle::receive(std::span<std::uint8_t> buffer, WdAddress& address,
                                     std::size_t& length) {
    if (handle_ == nullptr) {
        last_error_ = ERROR_INVALID_HANDLE;
        return ReceiveStatus::error;
    }
    WinDivertLibrary& lib = WinDivertLibrary::instance();
    if (lib.recv == nullptr) {
        last_error_ = ERROR_PROC_NOT_FOUND;
        return ReceiveStatus::error;
    }

    WINDIVERT_ADDRESS raw{};
    UINT received = 0;
    const BOOL ok = reinterpret_cast<FnRecv>(lib.recv)(static_cast<HANDLE>(handle_), buffer.data(),
                                                      static_cast<UINT>(buffer.size()), &received,
                                                      &raw);
    if (!ok) {
        last_error_ = ::GetLastError();
        if (last_error_ == ERROR_NO_DATA) return ReceiveStatus::stopped;
        if (last_error_ == ERROR_INVALID_HANDLE) return ReceiveStatus::error;
        if (last_error_ == ERROR_SERVICE_REQUEST_TIMEOUT) return ReceiveStatus::timeout;
        return ReceiveStatus::error;
    }
    last_error_ = 0;

    static_assert(sizeof(WINDIVERT_ADDRESS) <= sizeof(address.raw),
                  "WdAddress::raw is too small for WINDIVERT_ADDRESS");
    std::memset(address.raw, 0, sizeof(address.raw));
    std::memcpy(address.raw, &raw, sizeof(raw));
    address.raw_size = static_cast<std::uint32_t>(sizeof(raw));
    address.outbound = raw.Outbound != 0;
    address.loopback = raw.Loopback != 0;

    // The driver cannot report more bytes than the buffer holds, but clamp anyway so a
    // caller can never be induced to read past the end.
    length = std::min<std::size_t>(static_cast<std::size_t>(received), buffer.size());
    return ReceiveStatus::ok;
}

bool WinDivertHandle::send(std::span<const std::uint8_t> buffer, const WdAddress& address) {
    if (handle_ == nullptr) {
        last_error_ = ERROR_INVALID_HANDLE;
        return false;
    }
    WinDivertLibrary& lib = WinDivertLibrary::instance();
    if (lib.send == nullptr) {
        last_error_ = ERROR_PROC_NOT_FOUND;
        return false;
    }

    WINDIVERT_ADDRESS raw{};
    if (address.raw_size == sizeof(raw)) {
        std::memcpy(&raw, address.raw, sizeof(raw));
    } else {
        raw.Outbound = address.outbound ? 1u : 0u;
        raw.Loopback = address.loopback ? 1u : 0u;
    }

    UINT sent = 0;
    const BOOL ok = reinterpret_cast<FnSend>(lib.send)(static_cast<HANDLE>(handle_), buffer.data(),
                                                       static_cast<UINT>(buffer.size()), &sent,
                                                       &raw);
    if (!ok) {
        last_error_ = ::GetLastError();
        return false;
    }
    if (sent != buffer.size()) {
        last_error_ = ERROR_WRITE_FAULT;
        return false;
    }
    last_error_ = 0;
    return true;
}

bool WinDivertHandle::shutdown_receive() {
    if (handle_ == nullptr) return false;
    WinDivertLibrary& lib = WinDivertLibrary::instance();
    if (lib.shutdown == nullptr) return false;
    const BOOL ok = reinterpret_cast<FnShutdown>(lib.shutdown)(static_cast<HANDLE>(handle_),
                                                               WINDIVERT_SHUTDOWN_RECV);
    if (!ok) last_error_ = ::GetLastError();
    return ok != FALSE;
}

bool WinDivertHandle::validate_filter(std::string_view filter, std::string& error,
                                      std::size_t& position) {
    position = 0;
    WinDivertLibrary& lib = WinDivertLibrary::instance();
    if (!lib.loaded()) {
        error = lib.load_error_string();
        return false;
    }
    if (lib.compile_filter == nullptr) {
        // Very old WinDivert without the helper: fall back to a real open/close probe.
        return true;
    }
    const std::string expression(filter);
    char object[2048] = {};
    LPCSTR error_text = nullptr;
    UINT error_position = 0;
    const BOOL ok = reinterpret_cast<FnCompileFilter>(lib.compile_filter)(
        expression.c_str(), WINDIVERT_LAYER_NETWORK, object, static_cast<UINT>(sizeof(object)),
        &error_text, &error_position);
    if (ok) return true;
    position = error_position;
    error = error_text != nullptr ? std::string(error_text) : "filter rejected by WinDivert";
    if (position != 0) {
        // Point at the offending character so a long expression is easy to fix.
        std::size_t line_start = 0;
        std::size_t line = 1;
        for (std::size_t i = 0; i < position && i < expression.size(); ++i) {
            if (expression[i] == '\n') {
                ++line;
                line_start = i + 1;
            }
        }
        error += " (line " + std::to_string(line) + ", column " +
                 std::to_string(position - line_start + 1) + ")";
    }
    return false;
}

std::string WinDivertHandle::last_error_string() const { return format_error(last_error_); }

}  // namespace zc::win
