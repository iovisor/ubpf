# uBPF Test Organization

This directory contains tests that are specific to the uBPF implementation. General eBPF instruction conformance tests are located in `external/bpf_conformance/tests/` and are shared across multiple BPF runtime implementations.

## Test Structure

```
tests/
├── README.md                  # This file
├── *.data                     # Unique uBPF tests (not in conformance)
├── errors/                    # Error handling tests
│   └── err-*.data            # Tests that verify proper error detection
├── helpers/                   # Tests requiring uBPF-specific helpers
│   ├── call-memfrob.data     # Uses memfrob helper
│   ├── call-save.data        # Register preservation test
│   └── call.data             # Custom helper test
├── extensions/                # Tests for uBPF extensions
│   ├── call_local_use_stack.data  # Local call with stack usage
│   └── call_unwind.data      # Unwind extension test
├── elf/                       # ELF loader tests
│   └── *.data                # Tests for ELF file loading
├── tcp-port-80/               # TCP port 80 test data
└── tcp-sack/                  # TCP SACK test data
```

## Test Categories

### Error Handling Tests (`errors/`)
Tests that verify uBPF properly detects and reports various error conditions:
- Invalid instructions
- Out-of-bounds memory access
- Invalid jumps
- Stack overflow
- Register validation
- Instruction format errors

These tests typically expect the VM to fail gracefully with appropriate error messages.

### Helper Function Tests (`helpers/`)
Tests that rely on uBPF-specific helper functions registered with the VM. These cannot be run through the generic conformance framework without the specific helpers being available.

### Extension Tests (`extensions/`)
Tests for uBPF-specific extensions that are not part of the standard eBPF specification:
- Local function calls
- Stack unwinding

### ELF Loader Tests (`elf/`)
Tests for the uBPF ELF file loader, verifying correct parsing and error handling of ELF-formatted eBPF programs.

### Root-Level Tests
Tests in the root `tests/` directory are uBPF-specific tests that don't fit into the above categories but are not present in the bpf_conformance test suite. These may include:
- Edge cases specific to uBPF's implementation
- Performance-sensitive tests
- Tests for specific bug fixes
- Tests pending contribution to bpf_conformance

## Running Tests

All tests (both uBPF-specific and conformance) are automatically discovered and run through the bpf_conformance test framework when building with tests enabled:

```bash
cmake -S . -B build -DUBPF_ENABLE_TESTS=true
cmake --build build
cmake --build build --target test
```

Tests are run in both JIT and interpreter modes. Each `.data` file generates two test cases:
- `<test-name>.data-JIT` - Tests the JIT compiler
- `<test-name>.data-Interpreter` - Tests the interpreter

## Test Format

Test files use the `.data` format with sections marked by `--` prefixes:

```
-- asm
mov %r0, 1
exit

-- result
0x1

-- mem (optional)
00 11 22 33
```

See the bpf_conformance documentation for complete test format specification.

## Contributing Tests

When adding new tests:

1. **Instruction conformance tests** should be contributed to the [bpf_conformance](https://github.com/Alan-Jowett/bpf_conformance) repository
2. **uBPF-specific tests** should be added to the appropriate subdirectory in this `tests/` directory
3. **Error handling tests** should go in `errors/` with the `err-` prefix
4. **Tests requiring helpers** should go in `helpers/`
5. **Tests for extensions** should go in `extensions/`

This organization ensures:
- No duplicate tests between ubpf and bpf_conformance
- Clear separation of concerns
- Easy test discovery and maintenance
- Maximum test sharing across BPF implementations
