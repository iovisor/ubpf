# uBPF

Userspace eBPF VM

[![Main](https://github.com/iovisor/ubpf/actions/workflows/main.yml/badge.svg?branch=main)](https://github.com/iovisor/ubpf/actions/workflows/main.yml)
[![Coverage Status](https://coveralls.io/repos/iovisor/ubpf/badge.svg?branch=main&service=github)](https://coveralls.io/github/iovisor/ubpf?branch=master)

## About

This project aims to create an Apache-licensed library for executing eBPF programs. The primary implementation of eBPF lives in the Linux kernel, but due to its GPL license it can't be used in many projects.

[Linux documentation for the eBPF instruction set](https://www.kernel.org/doc/Documentation/networking/filter.txt)

[Instruction set reference](https://github.com/iovisor/bpf-docs/blob/master/eBPF.md)

[API Documentation](https://iovisor.github.io/ubpf)

This project includes an eBPF assembler, disassembler, interpreter (for all platforms),
and JIT compiler (for x86-64 and Arm64 targets).

## Checking Out

Before following any of the instructions below for [building](#building-with-cmake),
[testing](#running-the-tests), [contributing](#contributing), etc, please be
sure to properly check out the source code which requires properly initializing submodules:

```
git submodule init
git submodule update --recursive
```

## Building with CMake
Note: This works on Windows, Linux, and MacOS, provided the prerequisites are installed.
For a more detailed list of instructions, including list of dependencies,
see [CI/CD steps](.github/workflows/main.yml).
```
cmake -S . -B build -DUBPF_ENABLE_TESTS=true
cmake --build build --config Debug
```
## Running the tests

### Linux and MacOS native
```
cmake --build build --target test --
```

### Linux aarch64 cross-compile
Note: This requires qemu and the aarch64 toolchain.

To install the required tools (assuming Debian derived distro). For a more
detailed list of instructions, including list of dependencies, see
[CI/CD steps](.github/workflows/main.yml).
```
sudo apt install -y \
    g++-aarch64-linux-gnu \
    gcc-aarch64-linux-gnu \
    qemu-user
```

Building for aarch64.
```
# Build bpf_conformance natively as a workaround to missing boost libraries on aarch64.
cmake -S external/bpf_conformance -B build_bpf_conformance
cmake --build build_bpf_conformance
# Build ubpf for aarch64
cmake -S . -B build -DUBPF_ENABLE_TESTS=true -DUBPF_SKIP_EXTERNAL=true \
    -DBPF_CONFORMANCE_RUNNER="$(pwd)/build_bpf_conformance/bin/bpf_conformance_runner" \
    -DCMAKE_TOOLCHAIN_FILE=cmake/arm64.cmake
cmake --build build
cmake --build build --target test --
```

### Windows
```
ctest --test-dir build
```

## Building with make (Linux)
Run `make -C vm` to build the VM. This produces a static library `libubpf.a`
and a simple executable used by the testsuite. After building the
library you can install using `make -C vm install` via either root or
sudo.

## Running the tests (Linux)
To run the tests, you first need to build the vm code then use nosetests to execute the tests. Note: The tests have some dependencies that need to be present. See the [.travis.yml](https://github.com/iovisor/ubpf/blob/main/.travis.yml) for details.

### Before running the test (assuming Debian derived distro)
```
sudo apt-get update
sudo apt-get -y install python python-pip python-setuptools python-wheel python-nose
python2 -m pip install --upgrade "pip<21.0"
python2 -m pip install -r requirements.txt
python2 -m pip install cpp-coveralls
```

### Running the test
```
make -C vm COVERAGE=1
nosetests -v   # run tests
```

### After running the test
```
coveralls --gcov-options '\-lp' -i $PWD/vm/ubpf_vm.c -i $PWD/vm/ubpf_jit_x86_64.c -i $PWD/vm/ubpf_loader.c
```

## Compiling C to eBPF

You'll need [Clang 11](https://github.com/llvm/llvm-project/releases/tag/llvmorg-11.1.0).

    clang -g -O2 -target bpf -c prog.c -o prog.o

You can then pass the contents of `prog.o` to `ubpf_test`.

## Contributing

Please fork the project on GitHub and open a pull request. You can run all the
tests with `nosetests`.

## License

Copyright 2015, Big Switch Networks, Inc. Licensed under the Apache License, Version 2.0
<LICENSE.txt or http://www.apache.org/licenses/LICENSE-2.0>.
