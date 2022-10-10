#!/bin/bash
# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

# Work around for argument passing.
qemu-aarch64 -L /usr/aarch64-linux-gnu build/bin/ubpf_plugin "$*" --jit
