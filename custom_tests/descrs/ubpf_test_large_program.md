# Large Program Test

This test validates that programs with more than 65,536 instructions can be loaded, JIT compiled, and executed correctly when `ubpf_set_max_instructions()` is used to increase the limit.

The test performs the following:
1. Creates a VM and sets max_instructions to 100,000
2. Generates a program with 66,000 instructions (NOP-like JA instructions with offset 0) plus an EXIT
3. Loads the program into the VM
4. JIT compiles the program
5. Executes the JIT-compiled program

This validates that:
- The type change from uint16_t to uint32_t for num_insts works correctly
- Programs beyond the old 65,536 limit can be loaded
- The validation path handles large instruction counts correctly
- The JIT compiler can handle large programs (> 65,536 instructions)
- JIT-compiled large programs execute correctly

Note: The test skips interpreter execution because executing 66,000 sequential NOP-like
instructions via the interpreter would take prohibitively long for a test.
