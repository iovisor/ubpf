# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

set(CMAKE_CXX_STANDARD 20)

file(COPY ${CMAKE_SOURCE_DIR}/tests DESTINATION ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})

add_executable(
  ubpf_plugin
  ubpf_plugin.cc
)

target_include_directories("ubpf_plugin" PRIVATE
  "${CMAKE_SOURCE_DIR}/vm"
  "${CMAKE_BINARY_DIR}/vm"
  "${CMAKE_SOURCE_DIR}/vm/inc"
  "${CMAKE_BINARY_DIR}/vm/inc"
)

target_link_libraries(
  ubpf_plugin
  ubpf
  ubpf_settings
)
