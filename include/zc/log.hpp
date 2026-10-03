// Levelled logging.
//
// The hot path must never write a line per packet: at INFO level nothing is emitted
// for individual packets at all. Per-flow lines require --verbose, and per-packet detail
// requires --debug. Anything at ERROR or WARN is rate limited so a persistent condition
// cannot flood the terminal.
#pragma once

#include <cstdint>
#include <string_view>
#include <utility>

namespace zc::log {

enum class Level : std::uint8_t {
    error = 0,
    warn = 1,
    info = 2,
    debug = 3,
    trace = 4,
    off = 5,
};

[[nodiscard]] bool parse_level(std::string_view name, Level& out) noexcept;
[[nodiscard]] const char* level_name(Level level) noexcept;

// Installs the console handler so Ctrl+C asks the capture loop to stop.
using StopHandler = void (*)(void* context);
void set_stop_handler(StopHandler handler, void* context) noexcept;

[[nodiscard]] bool stopping() noexcept;
void request_stop() noexcept;

void set_level(Level level) noexcept;
[[nodiscard]] Level level() noexcept;

void emit(Level level, std::string_view message) noexcept;
void emitf(Level level, const char* format, ...) noexcept;

// Rate limited variant for conditions that can repeat per packet.
void emit_throttled(Level level, std::uint64_t interval_ms, std::string_view message) noexcept;

}  // namespace zc::log

#define ZC_LOG_ERROR(msg) ::zc::log::emit(::zc::log::Level::error, (msg))
#define ZC_LOG_WARN(msg) ::zc::log::emit(::zc::log::Level::warn, (msg))
#define ZC_LOG_INFO(msg) ::zc::log::emit(::zc::log::Level::info, (msg))
#define ZC_LOG_DEBUG(msg) ::zc::log::emit(::zc::log::Level::debug, (msg))
#define ZC_LOG_TRACE(msg) ::zc::log::emit(::zc::log::Level::trace, (msg))

#define ZC_LOG_AT(lvl, msg)                          \
    do {                                              \
        if (::zc::log::level() >= (lvl)) {            \
            ::zc::log::emit((lvl), (msg));            \
        }                                             \
    } while (0)
