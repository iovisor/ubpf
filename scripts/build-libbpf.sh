#!/usr/bin/bash
# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

git clone https://github.com/libbpf/libbpf.git
if [ $? -ne 0 ]; then
	echo "Could not clone the libbpf repository."
	exit 1
fi

# Jump in to the src directory to do the actual build.
cd libbpf/src

make
if [ $? -ne 0 ]; then
	echo "Could not build libbpf source."
	exit 1
fi

# Now that the build was successful, install the library (shared
# object and header files) in a spot where FindLibBpf.cmake can
# find it when it is being built.
sudo PREFIX=/usr LIBDIR=/usr/lib/x86_64-linux-gnu/ make install
exit 0
