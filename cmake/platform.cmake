#
# Copyright (c) 2022-present, IO Visor Project
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  set(PLATFORM_WINDOWS true)

elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
  set(PLATFORM_MACOS true)

elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  set(PLATFORM_LINUX true)
endif()
