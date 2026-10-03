#include "zc/log.hpp"

#include <array>
#include <atomic>
#include <chrono>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <vector>

namespace zc::log {
namespace {

std::atomic<Level> g_level{Level::info};
std::atomic<bool> g_stop{false};
StopHandler g_handler = nullptr;
void* g_handler_context = nullptr;
std::mutex g_write_mutex;

// Throttle slots, one per call site that uses emit_throttled.
constexpr std::size_t kThrottleSlots = 16;
std::mutex g_throttle_mutex;
std::uint64_t g_last[kThrottleSlots] = {};

std::uint64_t now_ms() noexcept {
    return static_cast<std::uint64_t>(
        std::chrono::steady_clock::now().time_since_epoch().count() / 1000000);
}

}  // namespace

bool parse_level(std::string_view name, Level& out) noexcept {
    if (name == "error") { out = Level::error; return true; }
    if (name == "warn" || name == "warning") { out = Level::warn; return true; }
    if (name == "info") { out = Level::info; return true; }
    if (name == "debug") { out = Level::debug; return true; }
    if (name == "trace") { out = Level::trace; return true; }
    if (name == "off" || name == "none" || name == "quiet") { out = Level::off; return true; }
    return false;
}

const char* level_name(Level level) noexcept {
    switch (level) {
    case Level::error: return "ERROR";
    case Level::warn: return "WARN";
    case Level::info: return "INFO";
    case Level::debug: return "DEBUG";
    case Level::trace: return "TRACE";
    case Level::off: return "OFF";
    }
    return "?";
}

void set_stop_handler(StopHandler handler, void* context) noexcept {
    g_handler = handler;
    g_handler_context = context;
}

bool stopping() noexcept { return g_stop.load(std::memory_order_acquire); }

void request_stop() noexcept {
    bool expected = false;
    if (g_stop.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
        if (g_handler != nullptr) g_handler(g_handler_context);
    }
}

void set_level(Level value) noexcept { g_level.store(value, std::memory_order_relaxed); }

Level level() noexcept { return g_level.load(std::memory_order_relaxed); }

void emit(Level level_value, std::string_view message) noexcept {
    if (g_level.load(std::memory_order_relaxed) < level_value) return;
    std::lock_guard<std::mutex> lock(g_write_mutex);
    std::fprintf(level_value <= Level::warn ? stderr : stdout, "[%s] %.*s\n",
                 level_name(level_value), static_cast<int>(message.size()), message.data());
}

void emitf(Level level_value, const char* format, ...) noexcept {
    if (g_level.load(std::memory_order_relaxed) < level_value) return;
    std::array<char, 512> buffer{};
    va_list args;
    va_start(args, format);
    const int written = std::vsnprintf(buffer.data(), buffer.size(), format, args);
    va_end(args);
    if (written <= 0) return;
    const std::size_t length =
        static_cast<std::size_t>(written) < buffer.size() ? static_cast<std::size_t>(written)
                                                           : buffer.size() - 1;
    std::lock_guard<std::mutex> lock(g_write_mutex);
    std::fprintf(level_value <= Level::warn ? stderr : stdout, "[%s] %.*s\n",
                 level_name(level_value), static_cast<int>(length), buffer.data());
}

void emit_throttled(Level level_value, std::uint64_t interval_ms,
                    std::string_view message) noexcept {
    if (g_level.load(std::memory_order_relaxed) < level_value) return;
    if (interval_ms == 0) {
        emit(level_value, message);
        return;
    }
    const std::uint64_t now = now_ms();
    std::lock_guard<std::mutex> lock(g_throttle_mutex);
    // Round-robin over a small fixed set of slots so independent call sites do not
    // starve each other.
    static thread_local std::size_t slot = 0;
    const std::size_t index = slot++ % kThrottleSlots;
    if (g_last[index] != 0 && now - g_last[index] < interval_ms) return;
    g_last[index] = now;
    emit(level_value, message);
}

}  // namespace zc::log
