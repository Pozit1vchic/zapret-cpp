// Runtime environment queries that only make sense on Windows.
#pragma once

#include <string>

namespace zc::win {

// True when the process token is a member of the built-in Administrators group.
[[nodiscard]] bool is_elevated();

// "10.0.26100.1234" for diagnostics.
[[nodiscard]] std::string os_version();

// "x64" / "arm64" / "x86", i.e. the architecture of the current process.
[[nodiscard]] std::string process_architecture();

// True when the OS can run native x64 binaries (always true for a 64-bit process).
[[nodiscard]] bool os_is_64bit();

// Installs the console control handler that turns Ctrl+C / close into a stop request.
void install_console_handler();

// True when a console is attached (so interactive prompts make sense).
[[nodiscard]] bool has_console();

}  // namespace zc::win
