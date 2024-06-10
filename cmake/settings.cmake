#
# Copyright (c) 2022-present, IO Visor Project
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

add_library("ubpf_settings" INTERFACE)

# Only configure our settings target if we are being built directly.
# If we are being used as a submodule, give a chance to the parent
# project to use the settings they want.
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  if(PLATFORM_LINUX OR PLATFORM_MACOS)
    target_compile_options("ubpf_settings" INTERFACE
      -Wall
      -Werror
      -Iinc
      -O2
      -Wunused-parameter
      -fPIC
    )

    if(CMAKE_BUILD_TYPE STREQUAL "Debug" OR
      CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")

      target_compile_options("ubpf_settings" INTERFACE
        -O0
        -g
      )
    endif()

    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
      target_compile_definitions("ubpf_settings" INTERFACE
        DEBUG
      )
    endif()

    if(UBPF_ENABLE_COVERAGE)
      target_compile_options("ubpf_settings" INTERFACE
        --coverage
        -fprofile-arcs
        -ftest-coverage
      )

      target_link_options("ubpf_settings" INTERFACE
        -fprofile-arcs
      )
    endif()

    if(UBPF_ENABLE_SANITIZERS)
      set(sanitizer_flags
        -fno-omit-frame-pointer
        -fsanitize=undefined,address
      )

      target_compile_options("ubpf_settings" INTERFACE
        ${sanitizer_flags}
      )

      target_link_options("ubpf_settings" INTERFACE
        ${sanitizer_flags}
      )
    endif()

    if(UBPF_ENABLE_LIBFUZZER)
      set(fuzzer_flags
        -g
        -O0
        -fsanitize=fuzzer
        -fsanitize=address
        -fsanitize-coverage=edge,indirect-calls,trace-cmp,trace-div,trace-gep
        )

      # Check if compiler is clang and emit error if not
        if(NOT CMAKE_C_COMPILER_ID STREQUAL "Clang")
            message(FATAL_ERROR "LibFuzzer is only supported with Clang")
        endif()

        target_compile_options("ubpf_settings" INTERFACE
            ${fuzzer_flags}
        )

        target_link_options("ubpf_settings" INTERFACE
            ${fuzzer_flags}
        )
    endif()
  elseif(PLATFORM_WINDOWS)
    set(CMAKE_VS_WINDOWS_TARGET_PLATFORM_VERSION "8.1")

    target_compile_options("ubpf_settings" INTERFACE
      /W4
    )

    target_compile_definitions("ubpf_settings" INTERFACE
      UNICODE
      _UNICODE

      $<$<CONFIG:Debug>:DEBUG>
      $<$<CONFIG:Release>:NDEBUG>
      $<$<CONFIG:RelWithDebInfo>:NDEBUG>
    )

  else()
    message(WARNING "ubpf - Unsupported platform")
  endif()
endif()

if(UBPF_ENABLE_INSTALL)
  install(
    TARGETS
      "ubpf_settings"

    EXPORT
      "ubpf"
  )
endif()

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
