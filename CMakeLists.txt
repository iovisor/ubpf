# Copyright (c) 2022-present, IO Visor Project
# SPDX-License-Identifier: Apache-2.0
#
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

include(ExternalProject)
cmake_minimum_required(VERSION 3.16)
project("ubpf")

include("cmake/platform.cmake")
include("cmake/settings.cmake")
include("cmake/options.cmake")
include("cmake/version.cmake")

if(UBPF_ENABLE_TESTS)
  include("CTest")
endif()

add_subdirectory("vm")

if(NOT UBPF_SKIP_EXTERNAL)
  ExternalProject_Add(Conformance
      INSTALL_COMMAND ""
      SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/external/bpf_conformance
      BINARY_DIR ${CMAKE_CURRENT_BINARY_DIR}/external/bpf_conformance
      EXCLUDE_FROM_ALL true
      STEP_TARGETS build)
endif()

if(UBPF_ENABLE_TESTS)
  add_subdirectory("custom_tests")
  add_subdirectory("ubpf_plugin")
  add_subdirectory("bpf")
  add_subdirectory("aarch64_test")
endif()

if(UBPF_ENABLE_PACKAGE)
  include("cmake/packaging.cmake")
endif()

if (UBPF_ENABLE_LIBFUZZER)
  if (PLATFORM_WINDOWS)
    # Set compiler flags for libfuzzer
    # Note: /fsanitize-coverage=inline-bool-flag causes link failures on Windows (missing _SancovBoolFlagUsed)
    # when building non-fuzzer executables like prevail's check.exe.
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /fsanitize=address /fsanitize-coverage=edge /fsanitize-coverage=trace-cmp /fsanitize-coverage=trace-div")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /fsanitize=address /fsanitize-coverage=edge /fsanitize-coverage=trace-cmp /fsanitize-coverage=trace-div")

    # Prevail adds a custom "FuzzerDebug" multi-config configuration on MSVC.
    # Ensure the corresponding CMake cache variables exist so generation succeeds.
    set(CMAKE_EXE_LINKER_FLAGS_FUZZERDEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG}" CACHE STRING "" FORCE)
    set(CMAKE_SHARED_LINKER_FLAGS_FUZZERDEBUG "${CMAKE_SHARED_LINKER_FLAGS_DEBUG}" CACHE STRING "" FORCE)
    set(CMAKE_MODULE_LINKER_FLAGS_FUZZERDEBUG "${CMAKE_MODULE_LINKER_FLAGS_DEBUG}" CACHE STRING "" FORCE)
  endif()
  add_subdirectory("libfuzzer")
  add_subdirectory("external/ebpf-verifier")

  # Prevail (and its bundled libbtf) enables LTO by default on Clang/GCC. In CI this can
  # fail due to LLVM toolchain version mismatches in the binutils LTO plugin, and our
  # fuzzing build does not need LTO.
  if(PLATFORM_LINUX OR PLATFORM_MACOS)
    foreach(_tgt IN ITEMS prevail libbtf)
      if(TARGET ${_tgt})
        set_property(TARGET ${_tgt} PROPERTY INTERPROCEDURAL_OPTIMIZATION FALSE)
        target_compile_options(${_tgt} PRIVATE -fno-lto)
      endif()
    endforeach()
  endif()
endif()
