## Test Description

This custom test guarantees that the uBPF runtime properly detects a user who sets a non-16-byte-aligned custom size for a local function's stack usage.

### eBPF Program Source

N/A

### Expected Behavior

An error reporting that a stack size for local functions of 17 bytes has the improper alignment.