# Copyright (c) 2022-present, IO Visor Project
# SPDX-License-Identifier: Apache-2.0
#
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

project("ubpf")
cmake_minimum_required(VERSION 3.16)

# Only run if not included as a subproject
if (CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
  set(UBPF_IS_TOP_LEVEL TRUE)
else()
  set(UBPF_IS_TOP_LEVEL FALSE)
endif()

if (UBPF_INSTALL_GIT_HOOKS AND UBPF_IS_TOP_LEVEL)
  # Install Git pre-commit hook
  file(COPY scripts/pre-commit scripts/commit-msg
       DESTINATION "${PROJECT_SOURCE_DIR}/.git/hooks")
endif()

include("cmake/platform.cmake")
include("cmake/settings.cmake")
include("cmake/options.cmake")
include("cmake/version.cmake")

if(UBPF_ENABLE_TESTS)
  include("CTest")
endif()

add_subdirectory("vm")

if(UBPF_ENABLE_TESTS)
  add_subdirectory("ubpf_plugin")
  if (NOT UBPF_SKIP_EXTERNAL)
    add_subdirectory("external")
  endif()
endif()

if(UBPF_ENABLE_PACKAGE)
  include("cmake/packaging.cmake")
endif()

