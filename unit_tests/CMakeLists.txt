#
# Copyright (c) 2022-present, IO Visor Project
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

set(CMAKE_CXX_STANDARD 20)

if(PLATFORM_LINUX)
  find_package(Boost REQUIRED)
  find_package(Boost_program_options REQUIRED)
  find_package(boost_filesystem REQUIRED)
  set(CMAKE_CXX_STANDARD 20)
  set(PLATFORM_LIB "boost_program_options" "boost_filesystem")
elseif(PLATFORM_MACOS)
  set(Boost_USE_STATIC_LIBS ON)
  find_package(Boost REQUIRED COMPONENTS program_options filesystem)
  set(CMAKE_CXX_STANDARD 20)
elseif(PLATFORM_WINDOWS)
  find_program(NUGET nuget)
  if(NOT NUGET)
    message("ERROR: You must first install nuget.exe from https://www.nuget.org/downloads")
  else()
    exec_program(${NUGET} ARGS install "Boost" -Version 1.80.0 -ExcludeVersion -OutputDirectory ${CMAKE_BINARY_DIR}/packages)
    exec_program(${NUGET} ARGS install "boost_filesystem-vc142" -Version 1.80.0 -ExcludeVersion -OutputDirectory ${CMAKE_BINARY_DIR}/packages)
    exec_program(${NUGET} ARGS install "boost_program_options-vc142" -Version 1.80.0 -ExcludeVersion -OutputDirectory ${CMAKE_BINARY_DIR}/packages)
  endif()
  set(Boost_INCLUDE_DIRS ${CMAKE_BINARY_DIR}/packages/boost/lib/native/include)
  set(Boost_LIBRARY_DIRS ${CMAKE_BINARY_DIR}/packages/boost_filesystem-vc142/lib/native ${CMAKE_BINARY_DIR}/packages/boost_program_options-vc142/lib/native)
endif()

include_directories(${Boost_INCLUDE_DIR})
link_directories(${Boost_LIBRARY_DIRS})

include(FetchContent)
FetchContent_Declare(
  googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG release-1.12.1
)

# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

enable_testing()

file(COPY ${CMAKE_SOURCE_DIR}/tests DESTINATION ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})

add_executable(
  ubpf_unit_test
  ubpf_unit_test.cc
)

target_include_directories("ubpf_unit_test" PRIVATE
  "${CMAKE_SOURCE_DIR}/external/bpf_conformance/include"
  "${Boost_INCLUDE_DIRS}"
)

if(PLATFORM_LINUX OR PLATFORM_MACOS)
  set(PLATFORM_LIBS ${PLATFORM_LIB} "dl" "pthread")
endif()

target_link_libraries(
  ubpf_unit_test
  GTest::gtest_main
  ubpf_settings
  bpf_conformance
  ${PLATFORM_LIBS}
)

include(GoogleTest)
gtest_discover_tests(ubpf_unit_test
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)