// Command line and configuration file handling.
//
// Precedence: built-in defaults < config file (--config) < command line flags.
// The CLI always wins so that a bad config file can be worked around without editing it.
#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

#include "zc/engine.hpp"
#include "zc/log.hpp"
#include "zc/rules.hpp"

namespace zc {

enum class RunMode : std::uint8_t {
    run = 0,
    help,
    version,
    check,       // local diagnostics, then exit
    list_rules,  // dump the compiled rule set, then exit
};

struct Options {
    RunMode mode = RunMode::run;

    // Configuration
    std::filesystem::path config_file;
    std::vector<std::filesystem::path> rule_files;
    std::vector<std::filesystem::path> exclude_files;
    std::vector<std::filesystem::path> hostlist_files;
    bool no_auto_files = false;

    // Capture
    std::string filter;          // empty -> built from the port lists
    bool filter_overridden = false;
    std::vector<std::uint16_t> tcp_ports{443, 8443, 2053, 2083, 2087, 2096};
    std::vector<std::uint16_t> http_tcp_ports{80, 8080};
    std::vector<std::uint16_t> udp_ports{443};
    bool all_tcp_ports = false;
    std::int16_t priority = 0;
    bool capture_loopback = false;

    // Engine
    EngineConfig engine;
    bool act_without_sni_cli = false;
    bool have_act_without_sni = false;

    // Runtime
    zc::log::Level log_level = zc::log::Level::info;
    bool stats = true;
    std::uint64_t stats_interval_ms = 0;
    std::uint64_t flow_capacity = 32768;
    std::uint64_t flow_ttl_ms = 300000;
    std::size_t flow_stream_budget = 4u << 20;  // 4 MiB total
    bool dry_run = false;

    // Provenance for the startup banner.
    std::vector<std::string> config_keys_used;
};

// Parses an INI-style configuration file. Unknown keys are reported, not ignored.
bool load_config_file(const std::filesystem::path& path, Options& options,
                      std::vector<std::string>& errors);

// Parses argv. Returns false and fills `error` on a bad option; `options.mode` tells
// the caller whether to continue.
bool parse_command_line(int argc, char** argv, Options& options, std::string& error);

[[nodiscard]] std::string usage_text(std::string_view executable);
[[nodiscard]] std::string version_text();

// Builds the WinDivert filter expression from the configured ports.
[[nodiscard]] std::string build_filter(const Options& options);

}  // namespace zc
