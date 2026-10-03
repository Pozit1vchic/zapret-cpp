// Tiny dependency-free test harness.
//
// zapret-cpp deliberately has no third-party test framework: the assertion surface is
// a handful of macros and keeping it in-tree means `ctest` works on MSYS2/Ninja,
// MSVC and Linux without any package manager.
#pragma once

#include <cstdio>
#include <cstdlib>
#include <string>
#include <string_view>
#include <vector>

namespace zctest {

inline int& failure_count() {
    static int count = 0;
    return count;
}

inline int& check_count() {
    static int count = 0;
    return count;
}

inline void report(bool ok, const char* expr, const char* file, int line,
                   std::string_view detail) {
    ++check_count();
    if (ok) return;
    ++failure_count();
    std::printf("[FAIL] %s:%d: %s", file, line, expr);
    if (!detail.empty()) {
        std::printf("  (%.*s)", static_cast<int>(detail.size()), detail.data());
    }
    std::printf("\n");
}

inline int finish(const char* suite) {
    if (failure_count() == 0) {
        std::printf("%s: %d checks passed\n", suite, check_count());
        return 0;
    }
    std::printf("%s: %d of %d checks FAILED\n", suite, failure_count(), check_count());
    return 1;
}

}  // namespace zctest

#define ZC_CHECK(expr) \
    ::zctest::report(static_cast<bool>(expr), #expr, __FILE__, __LINE__, {})

#define ZC_CHECK_MSG(expr, msg) \
    ::zctest::report(static_cast<bool>(expr), #expr, __FILE__, __LINE__, std::string_view(msg))

#define ZC_CHECK_EQ(a, b)                                                        \
    do {                                                                         \
        const auto zc_a = (a);                                                   \
        const auto zc_b = (b);                                                   \
        ::zctest::report(zc_a == zc_b, #a " == " #b, __FILE__, __LINE__, {});    \
    } while (0)

#define ZC_REQUIRE(expr)                                                        \
    do {                                                                         \
        if (!(expr)) {                                                           \
            ::zctest::report(false, #expr, __FILE__, __LINE__, {"fatal"});        \
            return;                                                              \
        }                                                                        \
    } while (0)

// Run `fn`, then print the summary. `fn` returns void; use ZC_REQUIRE to bail out.
#define ZC_TEST_MAIN(suite, fn)                                                  \
    int main() {                                                                 \
        fn();                                                                    \
        return ::zctest::finish(suite);                                          \
    }
