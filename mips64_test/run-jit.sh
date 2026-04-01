#!/bin/bash
# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: Apache-2.0

# Wrapper script for running ubpf_plugin with JIT mode on MIPS64
# Automatically detects if QEMU is needed (cross-compilation) or can run natively

if [ "$(uname -m)" = "mips64" ] || [ "$(uname -m)" = "mips64el" ]; then
    # Native MIPS64 - run directly
    ../bin/ubpf_plugin "$@" --jit
else
    # Cross-compiled - use QEMU
    qemu-mips64el -L /usr/mips64el-linux-gnuabi64 ../bin/ubpf_plugin "$@" --jit
fi
