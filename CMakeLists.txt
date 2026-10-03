cmake_minimum_required(VERSION 3.20)

project(zapret-cpp
        VERSION 3.0.0
        DESCRIPTION "Native WinDivert DPI desynchronization engine"
        LANGUAGES CXX)

# ---------------------------------------------------------------------------
# Build configuration
# ---------------------------------------------------------------------------
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
  set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS Debug Release RelWithDebInfo MinSizeRel)
endif()

option(ZC_BUILD_TESTS "Build the test suite" ON)
option(ZC_WERROR "Treat compiler warnings as errors" OFF)
option(ZC_NATIVE_ARCH "Optimize for the build machine's CPU" OFF)
set(ZC_SANITIZER "none" CACHE STRING "Sanitizer: none|address|undefined|address,undefined")
set_property(CACHE ZC_SANITIZER PROPERTY STRINGS none address undefined "address,undefined")

set(WINDIVERT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party/windivert"
    CACHE PATH "WinDivert SDK root (contains include/ and x64/)")

# ---------------------------------------------------------------------------
# Warning and hardening flags
# ---------------------------------------------------------------------------
function(zc_configure_target target)
  target_compile_features(${target} PUBLIC cxx_std_20)
  if(MSVC)
    target_compile_options(${target} PRIVATE /W4 /permissive- /utf-8 /Zc:__cplusplus)
    target_compile_definitions(${target} PRIVATE
      _CRT_SECURE_NO_WARNINGS NOMINMAX WIN32_LEAN_AND_MEAN)
    if(ZC_WERROR)
      target_compile_options(${target} PRIVATE /WX)
    endif()
  else()
    target_compile_options(${target} PRIVATE
      -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion
      -Wshadow -Wnon-virtual-dtor -Wcast-qual -Wdouble-promotion
      -Wformat=2 -Wnull-dereference)
    # Hardening that costs nothing on this workload.
    include(CheckCXXCompilerFlag)
    check_cxx_compiler_flag("-fstack-protector-strong" ZC_HAS_STACK_PROTECTOR)
    if(ZC_HAS_STACK_PROTECTOR)
      target_compile_options(${target} PRIVATE -fstack-protector-strong)
    endif()
    check_cxx_compiler_flag("-fno-strict-aliasing" ZC_HAS_NO_STRICT_ALIASING)
    if(ZC_HAS_NO_STRICT_ALIASING)
      target_compile_options(${target} PRIVATE -fno-strict-aliasing)
    endif()
    if(ZC_WERROR)
      target_compile_options(${target} PRIVATE -Werror)
    endif()
  endif()

  if(ZC_NATIVE_ARCH AND NOT MSVC)
    include(CheckCXXCompilerFlag)
    check_cxx_compiler_flag("-march=native" ZC_HAS_MARCH_NATIVE)
    if(ZC_HAS_MARCH_NATIVE)
      target_compile_options(${target} PRIVATE -march=native)
    endif()
  endif()

  if(NOT ZC_SANITIZER STREQUAL "none")
    if(MSVC)
      message(WARNING "Sanitizers are not enabled for MSVC; ignoring ZC_SANITIZER")
    else()
      target_compile_options(${target} PUBLIC -fsanitize=${ZC_SANITIZER} -fno-omit-frame-pointer -g)
      target_link_options(${target} PUBLIC -fsanitize=${ZC_SANITIZER})
    endif()
  endif()
endfunction()

# ---------------------------------------------------------------------------
# zapret_core: platform independent packet engine
# ---------------------------------------------------------------------------
add_library(zapret_core STATIC
  src/csum.cpp
  src/crypto.cpp
  src/packet.cpp
  src/tls.cpp
  src/http.cpp
  src/quic.cpp
  src/flow.cpp
  src/rules.cpp
  src/strategy.cpp
  src/engine.cpp
  src/stats.cpp
  src/log.cpp
  src/cli.cpp
)
target_include_directories(zapret_core PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>
)
zc_configure_target(zapret_core)

# ---------------------------------------------------------------------------
# Windows executable
# ---------------------------------------------------------------------------
if(WIN32)
  file(TO_CMAKE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/resources/app.manifest" ZC_MANIFEST_PATH)
  configure_file(resources/app.rc.in "${CMAKE_CURRENT_BINARY_DIR}/app.rc" @ONLY)

  add_executable(zapret-cpp
    src/app/main.cpp
    src/win/windivert.cpp
    src/win/sysinfo.cpp
    "${CMAKE_CURRENT_BINARY_DIR}/app.rc"
  )
  target_include_directories(zapret-cpp PRIVATE
    src
    "${WINDIVERT_DIR}/include"
  )
  target_link_libraries(zapret-cpp PRIVATE zapret_core advapi32)
  zc_configure_target(zapret-cpp)

  if(MINGW)
    # Static CRT keeps the release a single self-contained exe plus the WinDivert files.
    target_link_options(zapret-cpp PRIVATE -static -static-libgcc -static-libstdc++)
  endif()

  # -----------------------------------------------------------------------
  # WinDivert runtime deployment
  #
  # The whole point of this block: after a Release build the executable must be
  # runnable without the user copying anything by hand. The DLL and the driver are
  # copied next to zapret-cpp.exe as a post-build step.
  # -----------------------------------------------------------------------
  set(ZC_WINDIVERT_RUNTIME
    "${WINDIVERT_DIR}/x64/WinDivert.dll"
    "${WINDIVERT_DIR}/x64/WinDivert64.sys"
  )
  foreach(runtime_file IN LISTS ZC_WINDIVERT_RUNTIME)
    if(NOT EXISTS "${runtime_file}")
      message(FATAL_ERROR
        "Missing WinDivert runtime: ${runtime_file}\n"
        "Expected the WinDivert x64 runtime under ${WINDIVERT_DIR}/x64/.")
    endif()
  endforeach()

  add_custom_command(TARGET zapret-cpp POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${WINDIVERT_DIR}/x64/WinDivert.dll" "$<TARGET_FILE_DIR:zapret-cpp>/WinDivert.dll"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${WINDIVERT_DIR}/x64/WinDivert64.sys" "$<TARGET_FILE_DIR:zapret-cpp>/WinDivert64.sys"
    COMMENT "Deploying the WinDivert runtime next to zapret-cpp.exe"
    VERBATIM)

  # A ready-to-run directory: build the target, then `cmake --build build --target release`.
  set(ZC_RELEASE_DIR "${CMAKE_BINARY_DIR}/release" CACHE PATH
      "Directory populated by the 'release' target")
  add_custom_target(release
    COMMAND ${CMAKE_COMMAND} -E make_directory "${ZC_RELEASE_DIR}"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "$<TARGET_FILE:zapret-cpp>" "${ZC_RELEASE_DIR}/zapret-cpp.exe"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${WINDIVERT_DIR}/x64/WinDivert.dll" "${ZC_RELEASE_DIR}/WinDivert.dll"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${WINDIVERT_DIR}/x64/WinDivert64.sys" "${ZC_RELEASE_DIR}/WinDivert64.sys"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${WINDIVERT_DIR}/LICENSE" "${ZC_RELEASE_DIR}/WinDivert-LICENSE.txt"
    COMMAND ${CMAKE_COMMAND} -E copy_directory
            "${CMAKE_CURRENT_SOURCE_DIR}/config" "${ZC_RELEASE_DIR}/config"
    COMMAND ${CMAKE_COMMAND} -E copy_directory
            "${CMAKE_CURRENT_SOURCE_DIR}/lists" "${ZC_RELEASE_DIR}/lists"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CMAKE_CURRENT_SOURCE_DIR}/README.md" "${ZC_RELEASE_DIR}/README.md"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CMAKE_CURRENT_SOURCE_DIR}/AUDIT.md" "${ZC_RELEASE_DIR}/AUDIT.md"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CMAKE_CURRENT_SOURCE_DIR}/NOTICE.md" "${ZC_RELEASE_DIR}/NOTICE.md"
    DEPENDS zapret-cpp
    COMMENT "Assembling a runnable release directory in ${ZC_RELEASE_DIR}"
    VERBATIM)

  install(TARGETS zapret-cpp RUNTIME DESTINATION bin)
  install(FILES
    "${WINDIVERT_DIR}/x64/WinDivert.dll"
    "${WINDIVERT_DIR}/x64/WinDivert64.sys"
    DESTINATION bin)
  install(FILES "${WINDIVERT_DIR}/LICENSE" DESTINATION bin RENAME WinDivert-LICENSE.txt)
  install(DIRECTORY config lists DESTINATION bin)
  install(FILES README.md AUDIT.md NOTICE.md DESTINATION bin)
  install(TARGETS zapret_core ARCHIVE DESTINATION lib)
  install(DIRECTORY include/ DESTINATION include)
else()
  message(STATUS "zapret-cpp: building the portable core only (WinDivert backend needs Windows)")
endif()

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
if(ZC_BUILD_TESTS)
  enable_testing()

  # Every suite is a separate executable so a crash in one parser cannot hide the
  # results of the others, and so ctest reports which component actually broke.
  set(ZC_TEST_SUITES
    crypto quic tls http packet rules flow strategy engine cli fuzz
  )
  foreach(suite IN LISTS ZC_TEST_SUITES)
    set(suite_source "tests/test_${suite}.cpp")
    if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${suite_source}")
      message(STATUS "zapret-cpp: skipping test_${suite} (no ${suite_source})")
      continue()
    endif()
    add_executable(test_${suite} "${suite_source}")
    target_include_directories(test_${suite} PRIVATE
      "${CMAKE_CURRENT_SOURCE_DIR}/include"
      "${CMAKE_CURRENT_SOURCE_DIR}/tests")
    target_link_libraries(test_${suite} PRIVATE zapret_core)
    zc_configure_target(test_${suite})
    add_test(NAME ${suite} COMMAND test_${suite})
    set_tests_properties(${suite} PROPERTIES TIMEOUT 300)
  endforeach()

  # Fuzzing target: reads a corpus directory or generates pseudo-random inputs. Built
  # only when a sanitizer is requested so the default test run stays fast, and always
  # built on non-Windows so CI can run it on Linux with sanitizers.
  if(NOT WIN32 OR NOT ZC_SANITIZER STREQUAL "none")
    add_test(NAME fuzz_all COMMAND test_fuzz --iterations 20000)
  endif()
endif()
