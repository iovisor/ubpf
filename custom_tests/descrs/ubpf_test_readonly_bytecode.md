## Test Description

This test verifies that bytecode can be loaded and executed with read-only memory protection enabled.

The test validates:
1. Bytecode loads successfully with read-only protection enabled (default)
2. The VM executes the bytecode correctly with read-only protection
3. The `ubpf_toggle_readonly_bytecode()` API works correctly
4. Bytecode can be loaded with read-only protection disabled when toggled off
