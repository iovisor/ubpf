# Copyright (c) 2022-present, IO Visor Project
# SPDX-License-Identifier: Apache-2.0

#
# Copyright (c) 2022-present, IO Visor Project
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

include("CheckLibraryExists")
include("GNUInstallDirs")

find_path(UBPF_ELF_H_PATH "elf.h" NO_CACHE)
if(UBPF_ELF_H_PATH)
  set(UBPF_HAS_ELF_H true)
elseif(PLATFORM_MACOS)
  message(WARNING "ubpf - using compat ELF support for macOS.")
  set(UBPF_ELF_H_PATH_COMPAT "${PROJECT_SOURCE_DIR}/compat/macOS/")
  set(UBPF_HAS_ELF_H_COMPAT true)
  set(UBPF_HAS_ELF_H true)
else()
  message(WARNING "ubpf - elf.h was not found, disabling ELF support")
endif()

configure_file(
  ubpf_config.h.inc
  "${CMAKE_CURRENT_BINARY_DIR}/ubpf_config.h"
)

set(public_header_list
  inc/ubpf.h
  "${CMAKE_CURRENT_BINARY_DIR}/ubpf_config.h"
)

add_library("ubpf"
  ${public_header_list}

  ebpf.h
  ubpf_int.h
  ubpf_jit_arm64.c
  ubpf_jit.c
  ubpf_jit_x86_64.c
  ubpf_jit_x86_64.h
  ubpf_loader.c
  ubpf_vm.c
)

target_link_libraries("ubpf"
  PRIVATE
    "ubpf_settings"
)

target_include_directories("ubpf" PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/inc>
  $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>
  $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
  $<BUILD_INTERFACE:${UBPF_ELF_H_PATH_COMPAT}>
)

set_target_properties("ubpf" PROPERTIES
  PUBLIC_HEADER
    "${public_header_list}"
)

if(PLATFORM_LINUX)
  check_library_exists("m" "pow" "" "libm_found")

  if(libm_found)
    target_link_libraries("ubpf"
      PUBLIC
        "m"
    )
  endif()
endif()

if(UBPF_ENABLE_TESTS)
  add_executable("ubpf_test"
    test.c
  )

  target_link_libraries("ubpf_test"
    PRIVATE
      "ubpf_settings"
      "ubpf"
  )
endif()

add_subdirectory("compat")

if(TARGET "ubpf_compat")
  target_link_libraries("ubpf" PRIVATE
    $<BUILD_INTERFACE:ubpf_compat>
  )

  if(UBPF_ENABLE_TESTS)
    target_link_libraries("ubpf_test" PRIVATE
      $<BUILD_INTERFACE:ubpf_compat>
    )
  endif()

endif()


if(UBPF_ENABLE_INSTALL)
  install(
    TARGETS
      "ubpf"

    EXPORT
      "ubpf"

    LIBRARY DESTINATION
      "${CMAKE_INSTALL_LIBDIR}"

    PUBLIC_HEADER DESTINATION
      "${CMAKE_INSTALL_INCLUDEDIR}"
  )

  install(
    EXPORT
      "ubpf"

    DESTINATION
      "${CMAKE_INSTALL_LIBDIR}/cmake/ubpf"

    NAMESPACE
      "ubpf::"

    FILE
      "ubpfConfig.cmake"
  )
endif()
