# Copyright (c) 2022-present, IO Visor Project
# SPDX-License-Identifier: Apache-2.0
#
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#
# Shared test support configuration for uBPF tests and fuzzing

# Common include directories for all test-related targets
set(UBPF_TEST_INCLUDES
    "${CMAKE_SOURCE_DIR}/vm"
    "${CMAKE_BINARY_DIR}/vm"
    "${CMAKE_SOURCE_DIR}/vm/inc"
    "${CMAKE_BINARY_DIR}/vm/inc"
)

# Common libraries for all test-related targets
set(UBPF_TEST_LIBS
    ubpf
    ubpf_settings
)

# Helper function to add a test executable with common configuration
function(ubpf_add_test_executable name)
    add_executable(${name} ${ARGN})
    target_include_directories(${name} PRIVATE ${UBPF_TEST_INCLUDES})
    target_link_libraries(${name} PRIVATE ${UBPF_TEST_LIBS})
endfunction()
