# Constant Blinding Test

This test verifies the constant blinding feature in the uBPF JIT compiler.

## Test Description

The test performs the following:

1. Compiles a simple BPF program without constant blinding
2. Compiles the same program with constant blinding enabled
3. Verifies that both versions produce identical execution results
4. Compiles multiple times with blinding to ensure proper randomization

## Expected Behavior

- Programs with and without blinding should produce identical results
- JIT compilation should succeed in both modes
- The API should correctly enable/disable blinding
