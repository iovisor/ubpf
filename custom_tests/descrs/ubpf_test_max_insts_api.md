# Boundary and API Test

This test validates the boundary conditions and API for configurable instruction limits:

1. Test that 65,535 instructions (just under the default limit) load successfully
2. Test that 65,536 instructions (at the default limit) fail to load
3. Test that ubpf_set_max_instructions() works correctly
4. Test that ubpf_set_max_instructions() fails if code is already loaded
5. Test setting a lower limit than default

This ensures:
- The default limit of 65,536 is preserved for backward compatibility
- The API correctly validates and enforces limits
- Programs at the boundary behave as expected
