#
# Copyright (c) 2022-present, IO Visor Project
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

project("ubpf")
cmake_minimum_required(VERSION 3.16)

include("cmake/platform.cmake")
include("cmake/settings.cmake")
include("cmake/options.cmake")
include("cmake/version.cmake")

if(UBPF_ENABLE_TESTS)
  include("CTest")
endif()

add_subdirectory("vm")

if(UBPF_ENABLE_PACKAGE)
  include("cmake/packaging.cmake")
endif()

enable_testing()
add_test(NAME unit_tests
        COMMAND nosetests -v --where=${CMAKE_SOURCE_DIR})
