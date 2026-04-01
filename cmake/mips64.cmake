#
# Copyright (c) 2022-present, IO Visor Project
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR mips64)
set(CMAKE_SYSTEM_VERSION 1)
set(CMAKE_C_COMPILER /usr/bin/mips64el-linux-gnuabi64-gcc)
set(CMAKE_CXX_COMPILER /usr/bin/mips64el-linux-gnuabi64-g++)
set(CMAKE_C_FLAGS_INIT "-march=mips64r6")
set(CMAKE_CXX_FLAGS_INIT "-march=mips64r6")
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
