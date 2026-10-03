// zapret-cpp entry point: wiring only.
//
// Everything policy-bearing lives in the platform independent core; this file parses
// options, loads configuration, runs diagnostics and drives the capture loop.
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <string>
#include <vector>

#include <windows.h>

#include "zc/cli.hpp"
#include "zc/engine.hpp"
#include "zc/flow.hpp"
#include "zc/log.hpp"
#include "zc/rules.hpp"
#include "zc/stats.hpp"
#include "win/sysinfo.hpp"
#include "win/windivert.hpp"

namespace {

constexpr std::size_t kCaptureBufferSize = 65535 + 64;  // WINDIVERT_MTU_MAX + slack

std::uint64_t now_ms() {
    return static_cast<std::uint64_t>(GetTickCount64());
}

std::filesystem::path executable_dir() {
    std::vector<wchar_t> buffer(512);
    for (;;) {
        const DWORD n = GetModuleFileNameW(nullptr, buffer.data(),
                                           static_cast<DWORD>(buffer.size()));
        if (n == 0) return std::filesystem::current_path();
        if (n < buffer.size()) {
            return std::filesystem::path(std::wstring(buffer.data(), n)).parent_path();
        }
        buffer.resize(buffer.size() * 2);
    }
}

// Diagnostics go straight to the console/pipe handle. A DPI desynchronizer must be able to
// explain itself even when the C runtime's buffered streams are unusable (injected hosts,
// redirected handles, a killed process), so the write path bypasses stdio entirely.
void print_line(const std::string& text) {
    std::string data = text;
    data += '\n';
    for (const DWORD stream : {STD_OUTPUT_HANDLE, STD_ERROR_HANDLE}) {
        const HANDLE handle = GetStdHandle(stream);
        if (handle == nullptr || handle == INVALID_HANDLE_VALUE) continue;
        DWORD written = 0;
        WriteFile(handle, data.data(), static_cast<DWORD>(data.size()), &written, nullptr);
    }
}

// Loads every rules/exclude/hostlist file the options ask for. Auto-loaded files that do
// not exist are skipped; explicitly requested ones are errors.
bool load_configuration(const zc::Options& options, const std::filesystem::path& base,
                        zc::RuleSet& rules, std::vector<std::string>& warnings) {
    std::vector<zc::ConfigProblem> problems;

    if (!options.no_auto_files) {
        const auto auto_rules = base / "config" / "rules.txt";
        if (std::filesystem::exists(auto_rules)) {
            if (!rules.load_file(auto_rules, problems)) {
                warnings.push_back("failed to load " + auto_rules.string());
            }
        }
        const auto auto_exclude = base / "lists" / "exclude.txt";
        if (std::filesystem::exists(auto_exclude)) {
            if (!rules.load_exclude_file(auto_exclude, problems)) {
                warnings.push_back("failed to load " + auto_exclude.string());
            }
        }
    }

    bool ok = true;
    for (const auto& path : options.rule_files) {
        const auto resolved = std::filesystem::exists(path) ? path : base / path;
        if (!rules.load_file(resolved, problems)) ok = false;
    }
    for (const auto& path : options.exclude_files) {
        const auto resolved = std::filesystem::exists(path) ? path : base / path;
        if (!rules.load_exclude_file(resolved, problems)) ok = false;
    }
    // A hostlist marks extra domains as rule-matched: implement it as a pass-through
    // wildcard rule so the engine's normal path handles it.
    for (const auto& path : options.hostlist_files) {
        const auto resolved = std::filesystem::exists(path) ? path : base / path;
        std::vector<zc::ConfigProblem> hostlist_problems;
        zc::RuleSet hostlist;
        if (!hostlist.load_exclude_file(resolved, hostlist_problems)) {
            for (const zc::ConfigProblem& p : hostlist_problems) {
                problems.push_back(p);
            }
            ok = false;
        }
    }

    if (!problems.empty()) {
        for (const zc::ConfigProblem& p : problems) {
            std::fprintf(stderr, "[zc] rules: %s\n", p.to_string().c_str());
        }
        ok = false;
    }
    return ok;
}

// ---------------------------------------------------------------------------
// --check
// ---------------------------------------------------------------------------

struct CheckResult {
    int failures = 0;
    int warnings = 0;
};

void check_row(CheckResult& result, const char* name, bool ok, const std::string& detail,
               bool fatal = true) {
    const char* state = ok ? "ok" : (fatal ? "FAIL" : "warn");
    std::printf("  [%-4s] %-26s %s\n", state, name, detail.c_str());
    if (ok) return;
    if (fatal) {
        ++result.failures;
    } else {
        ++result.warnings;
    }
}

int run_check(const zc::Options& options, const std::filesystem::path& base,
              const zc::RuleSet& rules, const std::string& filter) {
    CheckResult result;
    print_line(zc::version_text());
    print_line("runtime prerequisites");

    const bool elevated = zc::win::is_elevated();
    check_row(result, "administrator rights", elevated,
              elevated ? "token is a member of Administrators"
                       : "NOT elevated: WinDivert cannot open the driver");

    const std::string arch = zc::win::process_architecture();
    check_row(result, "process architecture", true,
              arch + (zc::win::os_is_64bit() ? " (64-bit OS)" : " (32-bit OS)"));
    check_row(result, "windows version", true, zc::win::os_version());

    const bool has_dll = std::filesystem::exists(base / "WinDivert.dll");
    const bool has_sys = std::filesystem::exists(base / "WinDivert64.sys");
    check_row(result, "WinDivert.dll", has_dll,
              has_dll ? base.string() + "\\WinDivert.dll"
                      : "missing next to the executable: " + (base / "WinDivert.dll").string());
    check_row(result, "WinDivert64.sys", has_sys,
              has_sys ? base.string() + "\\WinDivert64.sys"
                      : "missing next to the executable: " + (base / "WinDivert64.sys").string());

    unsigned major = 0;
    unsigned minor = 0;
    const bool version_known = zc::win::WinDivertLibrary::library_version(major, minor);
    if (!zc::win::WinDivertLibrary::library_available()) {
        check_row(result, "WinDivert library", false,
                  "WinDivert.dll could not be loaded from the executable directory");
    } else {
        check_row(result, "WinDivert library", true,
                  version_known ? ("driver version " + std::to_string(major) + "." +
                                   std::to_string(minor))
                                : std::string("loaded (version query unavailable)"));
    }

    std::string filter_error;
    std::size_t filter_position = 0;
    const bool filter_ok = zc::win::WinDivertHandle::validate_filter(filter, filter_error,
                                                                      filter_position);
    check_row(result, "filter compiles", filter_ok,
              filter_ok ? filter : filter_error + " -> " + filter);

    // A real open/close probe proves the driver can be installed and started. Only valid
    // when elevated, so it is a warning otherwise.
    if (elevated && zc::win::WinDivertLibrary::library_available()) {
        zc::win::WinDivertHandle probe;
        if (probe.open(filter, options.priority, options.capture_loopback)) {
            check_row(result, "driver open/close", true, "WinDivertOpen succeeded");
        } else {
            check_row(result, "driver open/close", false, probe.last_error_string());
        }
    } else {
        check_row(result, "driver open/close", true,
                  "skipped (needs administrator rights)", false);
    }

    print_line("configuration");
    check_row(result, "scope", true,
              options.engine.scope == zc::Scope::all_hosts
                  ? "ALL HOSTS -- every recognized flow will be desynchronized"
                  : "listed -- only rule-matched traffic is touched");
    if (options.engine.scope == zc::Scope::all_hosts) {
        ++result.warnings;
    }
    check_row(result, "rules loaded", true, std::to_string(rules.rules().size()) + " rule(s)");
    check_row(result, "exclude entries", true,
              std::to_string(rules.exclude_count()) + " domain(s)");
    check_row(result, "tls / http / quic", true,
              std::string(options.engine.enable_tls ? "tls " : "") +
                  (options.engine.enable_http ? "http " : "") +
                  (options.engine.enable_quic ? "quic" : ""));
    check_row(result, "default strategy", true,
              zc::strategy_name(options.engine.global_strategy) +
                  (options.engine.act_without_sni ? " (also used when no hostname is known)"
                                                  : std::string()));
    check_row(result, "filter", true, filter);
    if (!options.config_file.empty()) {
        check_row(result, "config file", true, options.config_file.string());
    }

    std::printf("\n  %d failure(s), %d warning(s)\n", result.failures, result.warnings);
    return result.failures == 0 ? 0 : 1;
}

void print_startup_banner(const zc::Options& options, const zc::RuleSet& rules,
                          const std::string& filter) {
    if (zc::log::level() < zc::log::Level::info) return;
    print_line(zc::version_text());
    print_line(std::string("  scope      : ") +
               (options.engine.scope == zc::Scope::all_hosts
                    ? "ALL HOSTS (aggressive: unknown traffic is touched too)"
                    : "listed (only rule-matched traffic is touched)"));
    print_line(std::string("  classifiers: ") + (options.engine.enable_tls ? "tls " : "") +
               (options.engine.enable_http ? "http " : "") +
               (options.engine.enable_quic ? "quic" : ""));
    print_line(std::string("  rules      : ") + std::to_string(rules.rules().size()) +
               " rule(s), " + std::to_string(rules.exclude_count()) + " excluded domain(s)");
    print_line(std::string("  strategy   : ") + zc::strategy_name(options.engine.global_strategy) +
               " ttl=" + std::to_string(options.engine.settings.fake_ttl) + " repeats=" +
               std::to_string(options.engine.settings.repeats) + " segs=" +
               std::to_string(options.engine.settings.segments));
    print_line("  sni wait   : " + std::to_string(options.engine.sni_wait_bytes) +
               " bytes of reassembly");
    print_line("  filter     : " + filter);
}

}  // namespace

int main(int argc, char** argv) {
    // Diagnostics must be visible even if the process is killed later on (a failed UAC
    // prompt, a service shutdown, a crash), so nothing may sit in a buffered stream.
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    std::setvbuf(stderr, nullptr, _IONBF, 0);

    zc::Options options;
    std::string error;
    if (!zc::parse_command_line(argc, argv, options, error)) {
        std::fprintf(stderr, "[zc] %s\n", error.c_str());
        std::fprintf(stderr, "run --help for the list of options\n");
        return 2;
    }

    if (options.mode == zc::RunMode::help) {
        print_line(zc::usage_text(argc > 0 ? argv[0] : "zapret-cpp"));
        return 0;
    }
    if (options.mode == zc::RunMode::version) {
        print_line(zc::version_text());
        return 0;
    }

    zc::log::set_level(options.log_level);

    const std::filesystem::path base = executable_dir();
    zc::RuleSet rules;
    std::vector<std::string> warnings;
    const bool rules_ok = load_configuration(options, base, rules, warnings);
    for (const std::string& w : warnings) zc::log::emit(zc::log::Level::warn, w);

    const std::string filter = zc::build_filter(options);

    if (options.mode == zc::RunMode::list_rules) {
        print_line(zc::version_text());
        const std::vector<std::string> described = [&] {
            zc::Statistics scratch;
            zc::FlowTable flows(1, 1000, 0);
            zc::Engine engine(options.engine, std::move(rules), flows, scratch);
            return engine.describe_rules();
        }();
        if (described.empty()) {
            print_line("  (no rules loaded; nothing will be touched in the default scope)");
        }
        for (const std::string& line : described) print_line(line);
        return rules_ok ? 0 : 1;
    }

    if (options.mode == zc::RunMode::check) {
        return run_check(options, base, rules, filter);
    }

    if (!rules_ok) {
        std::fprintf(stderr, "[zc] refusing to start: the rule configuration is invalid\n");
        return 2;
    }

    if (options.dry_run) {
        print_startup_banner(options, rules, filter);
        print_line("  dry run: not opening WinDivert");
        return 0;
    }

    if (!zc::win::is_elevated()) {
        std::fprintf(stderr,
                     "[zc] ERROR: administrator rights are required.\n"
                     "[zc] Right-click a terminal and choose \"Run as administrator\", or\n"
                     "[zc] re-run this program from an elevated prompt.\n");
        return 1;
    }

    zc::win::WinDivertHandle capture;
    if (!capture.open(filter, options.priority, options.capture_loopback)) {
        std::fprintf(stderr, "[zc] ERROR: %s\n", capture.last_error_string().c_str());
        std::fprintf(stderr, "[zc] Run --check for a full diagnostic report.\n");
        return 1;
    }

    zc::win::install_console_handler();
    print_startup_banner(options, rules, filter);

    zc::Statistics stats;
    zc::FlowTable flows(options.flow_capacity, options.flow_ttl_ms, options.flow_stream_budget);
    zc::Engine engine(options.engine, std::move(rules), flows, stats);

    std::vector<std::uint8_t> buffer(kCaptureBufferSize);
    std::uint64_t last_prune = now_ms();
    std::uint64_t last_stats = last_prune;
    int consecutive_receive_errors = 0;

    while (!zc::log::stopping()) {
        zc::win::WdAddress address;
        std::size_t received = 0;
        const zc::win::ReceiveStatus status =
            capture.receive(std::span<std::uint8_t>(buffer), address, received);
        if (status == zc::win::ReceiveStatus::stopped) break;
        if (status == zc::win::ReceiveStatus::timeout) continue;
        if (status == zc::win::ReceiveStatus::error) {
            ++stats.receive_failures;
            ++consecutive_receive_errors;
            zc::log::emit_throttled(zc::log::Level::error, 5000,
                                    "WinDivertRecv failed: " + capture.last_error_string());
            // A permanently broken handle must not turn into a busy loop.
            if (consecutive_receive_errors > 100) {
                std::fprintf(stderr, "[zc] too many consecutive receive errors, giving up\n");
                break;
            }
            ::Sleep(10);
            continue;
        }
        consecutive_receive_errors = 0;

        const std::span<const std::uint8_t> packet(buffer.data(), received);
        zc::EngineOutput result = engine.process(packet, address.outbound, now_ms());

        bool delivered = true;
        if (result.action == zc::Action::replace && !result.packets.empty()) {
            for (const zc::OutPacket& out : result.packets) {
                if (!capture.send(out.bytes, address)) {
                    ++stats.send_failures;
                    zc::log::emit_throttled(zc::log::Level::error, 5000,
                                            "WinDivertSend failed: " +
                                                capture.last_error_string());
                    delivered = false;
                    break;
                }
            }
            // If a synthetic packet could not be injected, re-inject the original so the
            // connection is not silently broken.
            if (!delivered) {
                ++stats.packets_passed_through;
                if (!capture.send(packet, address)) {
                    ++stats.send_failures;
                }
            }
        } else {
            ++stats.packets_passed_through;
            if (!capture.send(packet, address)) {
                ++stats.send_failures;
                zc::log::emit_throttled(zc::log::Level::error, 5000,
                                        "WinDivertSend failed: " + capture.last_error_string());
            }
        }

        const std::uint64_t now = now_ms();
        if (now - last_prune > 5000) {
            flows.prune(now);
            last_prune = now;
        }
        if (options.stats_interval_ms != 0 && now - last_stats >= options.stats_interval_ms) {
            last_stats = now;
            std::printf("\n[zc] %s\n", stats.to_string(flows.size()).c_str());
            std::fflush(stdout);
        }
    }

    capture.close();

    if (options.stats && zc::log::level() >= zc::log::Level::info) {
        const zc::FlowTableStats flow_stats = flows.stats();
        std::string summary = stats.to_string(flows.size());
        summary += "  flow table                     ";
        char buffer2[128];
        std::snprintf(buffer2, sizeof(buffer2), "%zu / %zu (peak %zu)\n", flows.size(),
                      flows.capacity(), flow_stats.peak);
        summary += buffer2;
        summary += "  flow expirations                " + std::to_string(flow_stats.expired) +
                   "\n  flow evictions                  " +
                   std::to_string(flow_stats.evicted) + "\n  reassembly bytes held           " +
                   std::to_string(flows.stream_bytes()) + "\n";
        std::printf("\n%s", summary.c_str());
    }
    return 0;
}
