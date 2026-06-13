## Test Description

This test verifies that the safe execution profile is additive and interpreter-only.
It checks that:
1. `ubpf_set_execution_profile()` enables the safe profile before load.
2. The profile can no longer be changed after code is loaded.
3. JIT compilation is rejected for safe-profile VMs.
4. Interpreter execution still succeeds in the safe profile.
