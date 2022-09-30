#
# Copyright (c) 2022-present, IO Visor Project
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

set(CMAKE_CXX_STANDARD 20)

include(FetchContent)
FetchContent_Declare(
  googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG release-1.12.1
)

# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

if(UBPF_ENABLE_TESTS)
enable_testing()
endif()

add_executable(
  ubpf_unit_test
  bpf_assembler.cc
  code_gen_tests.cc
)

target_include_directories("ubpf_unit_test" PRIVATE
  "${CMAKE_SOURCE_DIR}/vm"
  "${CMAKE_BINARY_DIR}/vm"
  "${CMAKE_SOURCE_DIR}/vm/inc"
  "${CMAKE_BINARY_DIR}/vm/inc"
)

target_link_libraries(
  ubpf_unit_test
  GTest::gtest_main
  ubpf
  ubpf_settings
)

if (UBPF_ENABLE_TESTS)
include(GoogleTest)
gtest_discover_tests(ubpf_unit_test
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
  )
endif()