#
# Copyright (c) 2022-present, IO Visor Project
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

if(PLATFORM_WINDOWS)
  add_subdirectory("libraries")

  add_library("ubpf_compat" INTERFACE)
  target_sources("ubpf_compat" INTERFACE
    windows/sys/mman.h
    windows/sys/mman.c

    windows/endian.h

    windows/unistd.h
    windows/unistd.c
  )

  target_include_directories("ubpf_compat" INTERFACE
    windows
  )

  target_link_libraries("ubpf_compat" INTERFACE
    "external::win-c"
    "Ws2_32.lib"
  )

elseif(PLATFORM_MACOS)
  add_library("ubpf_compat" INTERFACE)

  target_sources("ubpf_compat" INTERFACE
    macos/endian.h
  )

  target_include_directories("ubpf_compat" INTERFACE
    macos
  )
endif()
