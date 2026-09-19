cmake_minimum_required(VERSION 3.16)
project(zapret-cpp LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

set(WINDIVERT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party/windivert"
    CACHE PATH "WinDivert SDK root (contains include/ and x64/)")

add_executable(zapret-cpp
  src/main.cpp
  src/csum.cpp
  src/tls.cpp
  src/packet.cpp
  src/desync.cpp
  src/services.cpp
  src/http.cpp
)

target_include_directories(zapret-cpp PRIVATE "${WINDIVERT_DIR}/include")

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
  set(WINDIVERT_ARCH x64)
else()
  set(WINDIVERT_ARCH x86)
endif()

target_link_libraries(zapret-cpp PRIVATE
  "${WINDIVERT_DIR}/${WINDIVERT_ARCH}/WinDivert.dll"
  ws2_32
  iphlpapi
)

add_executable(logic_test
  tests/logic_test.cpp
  src/csum.cpp
  src/tls.cpp
  src/services.cpp
  src/http.cpp
  src/packet.cpp
  src/desync.cpp
)
target_include_directories(logic_test PRIVATE src)
