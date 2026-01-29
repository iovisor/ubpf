# Test Reload Code Memory Leak

This test verifies that reloading code into a VM does not cause a memory leak.
Specifically, it tests that `vm->int_funcs` is properly freed when unloading code
before loading new code.
