// WinDivert backend.
//
// Everything WinDivert-specific lives behind this interface so the packet core stays
// platform independent and testable. The DLL is loaded dynamically and every entry point
// is resolved and null-checked before use; there is no path that calls through an
// unresolved pointer.
#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>

namespace zc::win {

// Opaque copy of WINDIVERT_ADDRESS so windivert.h does not leak into the rest of the
// project. WinDivert 2.x uses 80 bytes; the buffer is larger and the real size is
// recorded, so a future WinDivert cannot overflow it.
struct WdAddress {
    std::uint8_t raw[128]{};
    std::uint32_t raw_size = 0;
    bool outbound = false;
    bool loopback = false;
};

enum class ReceiveStatus : std::uint8_t {
    ok = 0,
    stopped,        // shutdown was requested
    timeout,
    error,
};

class WinDivertHandle {
public:
    WinDivertHandle() = default;
    ~WinDivertHandle();
    WinDivertHandle(const WinDivertHandle&) = delete;
    WinDivertHandle& operator=(const WinDivertHandle&) = delete;
    WinDivertHandle(WinDivertHandle&& other) noexcept;
    WinDivertHandle& operator=(WinDivertHandle&& other) noexcept;

    // Loads WinDivert.dll and opens a NETWORK-layer handle for `filter`.
    // Returns false and fills last_error() on failure.
    bool open(std::string_view filter, std::int16_t priority, bool allow_loopback);
    void close();
    [[nodiscard]] bool is_open() const noexcept { return handle_ != nullptr; }

    ReceiveStatus receive(std::span<std::uint8_t> buffer, WdAddress& address,
                                std::size_t& length);
    bool send(std::span<const std::uint8_t> buffer, const WdAddress& address);
    // Unblocks a receive that is waiting in the driver.
    bool shutdown_receive();

    [[nodiscard]] unsigned long last_error() const noexcept { return last_error_; }
    [[nodiscard]] std::string last_error_string() const;

    // Compile `filter` without opening a handle. Used by --check so a syntax error is
    // reported with its position instead of a generic WinDivert failure.
    static bool validate_filter(std::string_view filter, std::string& error, std::size_t& position);

    // WinDivert driver version, or false when the library is unavailable.
    static bool library_version(unsigned& major, unsigned& minor);
    static bool library_available();

private:
    void* handle_ = nullptr;
    unsigned long last_error_ = 0;
};

// Opaque module owner, so the DLL stays loaded while any handle exists.
class WinDivertLibrary {
public:
    static WinDivertLibrary& instance();
    [[nodiscard]] bool loaded() const noexcept { return module_ != nullptr; }
    [[nodiscard]] unsigned long load_error() const noexcept { return load_error_; }
    [[nodiscard]] std::string load_error_string() const;

    // Raw function pointers; null until the module is loaded.
    void* open = nullptr;
    void* close = nullptr;
    void* recv = nullptr;
    void* send = nullptr;
    void* shutdown = nullptr;
    void* get_param = nullptr;
    void* compile_filter = nullptr;
    void* calc_checksums = nullptr;

    // WinDivert driver version; false when the library is unavailable.
    static bool library_version(unsigned& major, unsigned& minor);
    static bool library_available();

private:
    WinDivertLibrary();
    void* module_ = nullptr;
    unsigned long load_error_ = 0;
};

}  // namespace zc::win
