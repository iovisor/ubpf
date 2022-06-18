#
# Copyright (c) 2022-present, IO Visor Project
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src")

add_library("win-c" EXCLUDE_FROM_ALL
  ${library_root}/include/getopt.h
  ${library_root}/source/getopt.c
)

target_include_directories("win-c" PUBLIC
  ${library_root}/include
)

target_link_libraries("win-c" PRIVATE
  "ubpf_settings"
)

add_library("external::win-c" ALIAS "win-c")
