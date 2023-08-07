# Copyright (c) 2022-present, IO Visor Project
# SPDX-License-Identifier: Apache-2.0
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

if(PLATFORM_LINUX OR PLATFORM_MACOS)
  option(UBPF_ENABLE_COVERAGE "Set to true to enable coverage flags")
  option(UBPF_ENABLE_SANITIZERS "Set to true to enable the address and undefined sanitizers")
endif()

option(UBPF_DISABLE_RETPOLINES "Disable retpoline security on indirect calls and jumps")
option(UBPF_ENABLE_INSTALL "Set to true to enable the install targets")
option(UBPF_ENABLE_TESTS "Set to true to enable tests")
option(UBPF_ENABLE_PACKAGE "Set to true to enable packaging")
option(UBPF_SKIP_EXTERNAL "Set to true to skip external projects")
option(UBPF_INSTALL_GIT_HOOKS "Set to true to install git hooks" ON)
option(BPF_CONFORMANCE_RUNNER "Set to use a custom bpf_conformance runner")

if(PLATFORM_MACOS)
  option(UBPF_ALTERNATE_LLVM_PATH "Set to the path for an alternate (non-Apple) LLVM that supports BPF")
endif()

# Note that the compile_commands.json file is only exporter when
# using the Ninja or Makefile generator
set(CMAKE_EXPORT_COMPILE_COMMANDS true CACHE BOOL "Set to true to generate the compile_commands.json file (forced on)" FORCE)
