cmake_minimum_required(VERSION 3.20)
project(nebulauth_sdk_cpp VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(GNUInstallDirs)

option(NEBULAUTH_BUILD_TESTS "Build NebulAuth C++ SDK tests" ON)

include(FetchContent)

FetchContent_Declare(
  nlohmann_json
  GIT_REPOSITORY https://github.com/nlohmann/json.git
  GIT_TAG v3.11.3
)
FetchContent_MakeAvailable(nlohmann_json)

FetchContent_Declare(
  httplib
  GIT_REPOSITORY https://github.com/yhirose/cpp-httplib.git
  GIT_TAG v0.18.6
)
FetchContent_MakeAvailable(httplib)

find_package(OpenSSL REQUIRED)

add_library(nebulauth_sdk
  src/NebulAuthClient.cpp
)

target_include_directories(nebulauth_sdk
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

target_link_libraries(nebulauth_sdk
  PUBLIC
    httplib::httplib
    nlohmann_json::nlohmann_json
    OpenSSL::SSL
    OpenSSL::Crypto
)

target_compile_definitions(nebulauth_sdk PUBLIC CPPHTTPLIB_OPENSSL_SUPPORT)

install(
  TARGETS nebulauth_sdk
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(
  DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

if(NEBULAUTH_BUILD_TESTS)
  include(CTest)
  enable_testing()

  FetchContent_Declare(
    Catch2
    GIT_REPOSITORY https://github.com/catchorg/Catch2.git
    GIT_TAG v3.6.0
  )
  FetchContent_MakeAvailable(Catch2)

  add_executable(nebulauth_sdk_tests
    tests/test_client.cpp
    tests/test_live.cpp
  )

  target_link_libraries(nebulauth_sdk_tests
    PRIVATE
      nebulauth_sdk
      Catch2::Catch2WithMain
      httplib::httplib
  )

  include(Catch)
  catch_discover_tests(nebulauth_sdk_tests)
endif()
