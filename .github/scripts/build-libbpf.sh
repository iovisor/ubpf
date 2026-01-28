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
# Detect the correct library directory for the architecture
ARCH=$(dpkg-architecture -qDEB_HOST_MULTIARCH 2>/dev/null)
if [ -z "$ARCH" ]; then
	# Fallback if dpkg-architecture is not available
	ARCH=$(gcc -print-multiarch 2>/dev/null)
fi
if [ -z "$ARCH" ]; then
	# Final fallback based on machine architecture
	MACHINE=$(uname -m)
	if [ "$MACHINE" = "aarch64" ]; then
		ARCH="aarch64-linux-gnu"
	else
		ARCH="x86_64-linux-gnu"
	fi
fi

sudo PREFIX=/usr LIBDIR=/usr/lib/${ARCH}/ make install
exit 0
