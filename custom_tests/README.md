## Writing a uBPF Custom Tests

Custom tests are enabled by creating two (2) or three (3) different files in the `custom_tests` directory.

### Files Of a uBPF Custom Test

#### Description Files

The first file to create is the Description File. The Description File is a file with a `.md` extension that resides in the `descrs` directory. The purpose of this file is to identify the name of the test (everything before the `.md` extension) and provide a place to document the purpose of the test.

#### Source Files

The second file to create is the Source File. The Source file should reside in the `srcs` directory and have a name that matches its Description File (with the `.cc` extension rather than the `.md` extension).

#### Input Files

The final file is optional. The Input File resides in the `data` directory and should have the same name as the other two (2) files but with an `.input` extension rather than  `.cc` or `.md` for the Source and Description File respectively. If present, the contents of this file will be given to the executed custom test over standard input.

### Building

The Source Files for a custom test are compiled using C++20 and are saved as an executable named according to the name of the test in the CMake build directory.

### Return Values

All successful tests should return `0`. All failing tests should return something other than `0`.

### Supporting Libraries

To reduce the boilerplate needed to write custom tests, there is a custom test library with several helpful functions. These functions are documented in the library's header file (`custom_tests/srcs/ubpf_custom_test_support.h`).

### Putting It Together

After describing the test's purpose in a Markdown syntax in a file named, say, `test_example.md` and stored in the `descrs` directory, you can write the test's Source Code (in C++20) and give it the name `test_example.cc` in the `srcs` directory. If the test needs input, you can save that input in the tests Input File (`test_input.input`) in the `data` directory.

Because all the files are present, this test will be run when the CTest target is invoked. Because there the optional `test_input.input` file is present, the contents of that file will be given to the executable via standard input.