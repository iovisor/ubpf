# Large Program Test

This test validates that programs with more than 65,536 instructions can be loaded correctly when `ubpf_set_max_instructions()` is used to increase the limit.

The test performs the following:
1. Creates a VM and sets max_instructions to 100,000
2. Generates a program with 66,000 instructions (NOP-like JA instructions with offset 0) plus an EXIT
3. Loads the program into the VM

This validates that:
- The type change from uint16_t to uint32_t for num_insts works correctly
- Programs beyond the old 65,536 limit can be loaded
- The validation path handles large instruction counts correctly

Note: The test skips interpreter and JIT execution to keep test runtime reasonable.
Large programs with many sequential NOPs would take prohibitively long to execute.
