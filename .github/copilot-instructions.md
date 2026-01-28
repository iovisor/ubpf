# Copilot Instructions for uBPF

## Project Overview

uBPF is a userspace eBPF virtual machine providing an Apache-licensed library for executing eBPF programs. It includes an eBPF assembler, disassembler, interpreter (all platforms), and JIT compiler (x86-64 and ARM64).

## Build and Test Commands

### Prerequisites
- Initialize submodules: `git submodule update --init --recursive`
- Windows: Visual Studio with MSVC and `nuget.exe` in PATH
- Linux: Run `./scripts/build-libbpf.sh`
- macOS: Install boost and optionally LLVM via Homebrew

### Build
```bash
cmake -S . -B build -DUBPF_ENABLE_TESTS=true
cmake --build build --config Debug
```

### Run All Tests
```bash
# Linux/macOS
cmake --build build --target test

# Windows
ctest --test-dir build
```

### Run a Single Test
```bash
# Run specific CTest by name pattern
ctest --test-dir build -R <test-name-pattern>

# Run Python tests directly (requires build first)
cd test_framework && python -m pytest test_vm.py::test_datafiles -k "add"
```

### Format Code
```bash
./scripts/format-code      # Linux/macOS
./scripts/format-code.ps1  # Windows
```

## Architecture

### Core Components
- **`vm/`** - Core uBPF library (C)
  - `ubpf_vm.c` - Interpreter implementation
  - `ubpf_jit_x86_64.c` - x86-64 JIT compiler
  - `ubpf_jit_arm64.c` - ARM64 JIT compiler
  - `ubpf_loader.c` - ELF loader
  - `inc/ubpf.h` - Public API header

- **`ubpf/`** - Python assembler/disassembler tools

- **`ubpf_plugin/`** - BPF conformance test plugin

### Test Structure
- **`tests/`** - Data-driven test files (`.data` format with `-- asm`, `-- result`, `-- mem` sections)
- **`test_framework/`** - Python test runners using nose
- **`custom_tests/`** - C++ tests for scenarios needing custom setup
  - Each test has: `descrs/<name>.md`, `srcs/<name>.cc`, optionally `data/<name>.input`
  - Built with C++20

### Key VM APIs
```c
struct ubpf_vm* ubpf_create(void);
int ubpf_load(struct ubpf_vm* vm, const void* code, uint32_t code_len, char** errmsg);
int ubpf_exec(const struct ubpf_vm* vm, void* mem, size_t mem_len, uint64_t* result);
ubpf_jit_fn ubpf_compile(struct ubpf_vm* vm, char** errmsg);
```

## Coding Conventions

### Style
- LLVM-based style with Mozilla brace rules (see `.clang-format`)
- 120 column width
- `clang-format` version 11+ required

### Naming
- `lower_snake_case` for variables, functions, file names
- `UPPER_SNAKE_CASE` for macros and constants
- Prefix public API with `ubpf_`
- Prefix internal/static functions with `_`
- Structs: prefix with `_`, typedef with `_t` suffix
  ```c
  typedef struct _ubpf_widget {
      uint64_t count;
  } ubpf_widget_t;
  ```

### Types and Headers
- Use fixed-width types from `stdint.h` (`int64_t`, `uint8_t`, not `long`, `unsigned char`)
- Use `const` and `static` to limit scope
- Headers must be self-contained (include their dependencies)
- Use Doxygen comments with `[in]`/`[out]` annotations for public APIs

### License Header
All new files require:
```c
// Copyright (c) <Contributor>
// SPDX-License-Identifier: Apache-2.0
```

### Pre-commit Hooks
The repository uses pre-commit hooks for:
- Secret detection (gitleaks)
- Shell script linting (shellcheck)
- C++ linting (cpplint)
- Python linting (pylint)
- Trailing whitespace and EOF fixes
