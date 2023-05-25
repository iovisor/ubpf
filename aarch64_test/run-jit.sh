#!/bin/bash
# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: Apache-2.0

# Work around for argument passing.
qemu-aarch64 -L /usr/aarch64-linux-gnu ../bin/ubpf_plugin "$*" --jit
