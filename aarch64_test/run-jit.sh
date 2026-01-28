#!/bin/bash
# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: Apache-2.0

# Wrapper script for running ubpf_plugin with JIT mode
# Automatically detects if QEMU is needed (cross-compilation) or can run natively

# Check if we're running on native ARM64 or need QEMU
if [ "$(uname -m)" = "aarch64" ]; then
    # Native ARM64 - run directly
    ../bin/ubpf_plugin "$@" --jit
else
    # Cross-compiled - use QEMU
    qemu-aarch64 -L /usr/aarch64-linux-gnu ../bin/ubpf_plugin "$@" --jit
fi
