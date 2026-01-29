# Large Program Test

This test validates that programs with more than 65,536 instructions can be loaded and executed correctly when `ubpf_set_max_instructions()` is used to increase the limit.

The test performs the following:
1. Creates a VM and sets max_instructions to 100,000
2. Generates a program with 70,000 instructions (NOP-like JA instructions with offset 0) plus an EXIT
3. Loads the program into the VM
4. Executes the program via interpreter
5. JIT compiles and executes the program
6. Verifies both return the same result

This validates that:
- The type change from uint16_t to uint32_t for num_insts works correctly
- Programs beyond the old 65,536 limit can be loaded
- The validation and execution paths handle large instruction counts
- The JIT compiler can handle large programs
