# MEMSX Support for bpf_conformance

## Issue
The CI tests are failing because the test infrastructure uses a C++ assembler from the `external/bpf_conformance` submodule, which doesn't recognize the new MEMSX mnemonics (`ldxbsx`, `ldxhsx`, `ldxwsx`).

## Solution
The patch file `bpf_conformance_memsx.patch` contains the necessary changes to add MEMSX support to the bpf_conformance assembler.

### Changes Required in bpf_conformance:

1. **src/ebpf.h**: Add EBPF_MODE_MEMSX constant and EBPF_OP_LDXBSX/LDXHSX/LDXWSX opcode definitions
2. **src/bpf_assembler.cc**: Add mnemonic handling for ldxbsx, ldxhsx, ldxwsx instructions

### Application
This patch should be applied to the bpf_conformance repository (https://github.com/Alan-Jowett/bpf_conformance) and then the submodule reference in ubpf should be updated to point to the new commit.

Alternatively, the patch can be applied locally for testing:
```bash
cd external/bpf_conformance
git apply ../../bpf_conformance_memsx.patch
```

## Note
The Python assembler in `ubpf/assembler.py` already has full MEMSX support from the initial implementation commits.
