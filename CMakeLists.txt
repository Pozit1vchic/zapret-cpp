cmake_minimum_required(VERSION 3.16)
project(zapret-cpp LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

set(WINDIVERT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party/windivert"
    CACHE PATH "WinDivert SDK root (contains include/)")

set(SOURCES
  src/main.cpp
  src/csum.cpp
  src/tls.cpp
  src/packet.cpp
  src/desync.cpp
  src/services.cpp
  src/http.cpp
  src/quic.cpp
  src/windivert_dyn.cpp
)

add_executable(zapret-cpp ${SOURCES})

target_include_directories(zapret-cpp PRIVATE
  src
  "${WINDIVERT_DIR}/include"
)

target_link_libraries(zapret-cpp PRIVATE ws2_32 iphlpapi)

if(MINGW)
  target_link_options(zapret-cpp PRIVATE
    -static
    -static-libgcc
    -static-libstdc++
  )
endif()

if(NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
  target_link_options(zapret-cpp PRIVATE -s)
endif()

add_executable(logic_test
  tests/logic_test.cpp
  src/csum.cpp
  src/tls.cpp
  src/services.cpp
  src/http.cpp
  src/packet.cpp
  src/desync.cpp
  src/quic.cpp
)
target_include_directories(logic_test PRIVATE src)

if(MINGW)
  target_link_options(logic_test PRIVATE -static -static-libgcc -static-libstdc++)
endif()
