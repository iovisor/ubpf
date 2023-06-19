# uBPF

Userspace eBPF VM

[![Build Status](https://travis-ci.org/iovisor/ubpf.svg?branch=master)](https://travis-ci.org/iovisor/ubpf)
[![Coverage Status](https://coveralls.io/repos/iovisor/ubpf/badge.svg?branch=master&service=github)](https://coveralls.io/github/iovisor/ubpf?branch=master)

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
A build system for compiling and testing ubpf is generated for Windows, Linux and macOS platforms using [`cmake`](https://cmake.org/):

```
cmake -S . -B build -DUBPF_ENABLE_TESTS=true
cmake --build build --config Debug
```

In order to prepare your system to successfully generate the build system using CMake, follow the platform-specific instructions below.

### Windows

Building, compiling and testing on Windows requires an installation of Visual Studio (*not* VS Code -- the MSVC compiler is necessary!).

> Note: There are free-to-use versions of Visual Studio for individual developers. These versions are known as the [community version](https://visualstudio.microsoft.com/vs/community/).

You *can* build, compile and test uBPF using [VS Code but Visual Studio is still required](https://code.visualstudio.com/docs/cpp/config-msvc).

The other requirement is that you have [`nuget.exe`](https://learn.microsoft.com/en-us/nuget/install-nuget-client-tools) in your `PATH`. You can determine if your host meets this criteria by testing whether

```console
> nuget.exe
```

produces output about how to execute the program. With `nuget.exe` installed, the `cmake` configuration system will download all the required developer libraries as it configures the build system.

### macOS
First, make sure that you have the XCode Command Line Tools installed:

```console
$ xcode-select -install
```

Installing the XCode Command Linux Tools will install Apple's version of the Clang compiler and other developer-support tools.

uBpf requires that your host have several support libraries installed. The easiest way to configure your host to meet these requirements,

1. Install [homebrew](https://brew.sh/)
2. Install [boost](https://www.boost.org/):
```console
$ brew install boost
```
3. Install [LLVM](https://llvm.org/) (and related tools):
```console
$ brew install llvm cmake
$ brew install clang-format
```

Installing LLVM from Homebrew is optional for developing and using uBPF on macOS. It is required if you plan on compiling/creating eBPF programs by compiling LLVM and storing them in ELF files. If you *do* install LLVM from Homebrew, add `-DUBPF_ALTERNATE_LLVM_PATH=/opt/homebrew/opt/llvm/bin` to the `cmake` configuration command:

```console
cmake -S . -B build -DUBPF_ENABLE_TESTS=true -DUBPF_ALTERNATE_LLVM_PATH=/opt/homebrew/opt/llvm/bin
```

### Linux
TBD

## Running the tests

### Linux and MacOS
```
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
To run the tests, you first need to build the vm code then use nosetests to execute the tests. Note: The tests have some dependencies that need to be present. See the [.travis.yml](https://github.com/iovisor/ubpf/blob/master/.travis.yml) for details.

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

You'll need [Clang 3.7](http://llvm.org/releases/download.html#3.7.0).

    clang-3.7 -O2 -target bpf -c prog.c -o prog.o

You can then pass the contents of `prog.o` to `ubpf_load_elf`, or to the stdin of
the `vm/test` binary.

## Contributing

Please fork the project on GitHub and open a pull request. You can run all the
tests with `nosetests`.

## License

Copyright 2015, Big Switch Networks, Inc. Licensed under the Apache License, Version 2.0
<LICENSE.txt or http://www.apache.org/licenses/LICENSE-2.0>.
