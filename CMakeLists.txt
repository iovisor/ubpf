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
    ExternalProject_Add(Conformance
        INSTALL_COMMAND ""
        SOURCE_DIR ${CMAKE_SOURCE_DIR}/external/bpf_conformance
				BINARY_DIR ${CMAKE_BINARY_DIR}/external/bpf_conformance
        EXCLUDE_FROM_ALL true
        STEP_TARGETS build)

if(UBPF_ENABLE_TESTS)
  add_subdirectory("ubpf_plugin")
  if (NOT UBPF_SKIP_EXTERNAL)
  endif()
  add_subdirectory("bpf")
  add_subdirectory("aarch64_test")
endif()

if(UBPF_ENABLE_PACKAGE)
  include("cmake/packaging.cmake")
endif()

