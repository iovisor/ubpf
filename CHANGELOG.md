*In compliance with the [APACHE-2.0](https://opensource.org/licenses/Apache-2.0) license: I declare that this version of the program contains my modifications, which can be seen through the usual "git" mechanism.*  


2022-12  
Contributor(s):  
Alan Jowett  
>Add link to API doc to readme (#169)* Add link to API doc to readme

Signed-off-by: Alan Jowett <alanjo@microsoft.com>

* PR feedback

Signed-off-by: Alan Jowett <alanjo@microsoft.com>

Signed-off-by: Alan Jowett <alanjo@microsoft.com>  
- - - - - - - - - - - - - - - - - - - - - - - - - - - 


2022-11  
Contributor(s):  
Alan Jowett  
adriaanjacobs  
>Add support for C++ users (#184)  
>Fix sign mismatch (#188)  
- - - - - - - - - - - - - - - - - - - - - - - - - - - 


2022-10  
Contributor(s):  
Matthew Gretton-Dann  
Alan Jowett  
>Add license check and formatting check (#156)Add docs/Contributing.md
Add .editorconfig
Apply clang formatting to existing files

Signed-off-by: Alan Jowett <alanjo@microsoft.com>

Signed-off-by: Alan Jowett <alanjo@microsoft.com>  
>Rename license to LICENSE.txt to comply with OpenSSF standards (#134)Signed-off-by: Alan Jowett <alanjo@microsoft.com>

Signed-off-by: Alan Jowett <alanjo@microsoft.com>  
>Reject EBPF_OP_LDDW if src != 0 (#132)Signed-off-by: Alan Jowett <alanjo@microsoft.com>  
>Fix potential integer overflow loading ELF files (#148)When loading ELF files we calculate the location of a section header in
a way that can overflow a `uint32_t` value producing a wrong result.

This commit fixes the issue by using the fact that section headers are
contiguous in the ELF file.

Signed-off-by: Matthew Gretton-Dann <matthew.gretton-dann@arm.com>

Signed-off-by: Matthew Gretton-Dann <matthew.gretton-dann@arm.com>  
>Remove unused string table code (#165)Signed-off-by: Alan Jowett <alanjo@microsoft.com>  
>Fix all UBSan failures on Arm64 (#154)* Add UBSan to the list of sanitizers

Signed-off-by: Matthew Gretton-Dann <matthew.gretton-dann@arm.com>

* Fix alignment warnings when reading ELF files

The undefined behaviour sanitizer issues warnings when processing ELF
files as the relocation and symbol structures may not be naturally
aligned in memory.

We solve this by memcpy'ing the appropriate data into a temporary
variable.

This isn't necessarily very performant - but this isn't performance
critical code.

Signed-off-by: Matthew Gretton-Dann <matthew.gretton-dann@arm.com>

* Fix undefined behaviours in integer promotions

The Undefined Behaviour Sanitizer was reporting issues with how
instruction bit patterns were generated.  This is due to integer
promotion rules.

This commit fixes all these problems by making the unsignedness of
values more explicit.

Signed-off-by: Matthew Gretton-Dann <matthew.gretton-dann@arm.com>

* Limit macOS to aligned load/store

Signed-off-by: Alan Jowett <alanjo@microsoft.com>

Signed-off-by: Matthew Gretton-Dann <matthew.gretton-dann@arm.com>
Signed-off-by: Alan Jowett <alanjo@microsoft.com>
Co-authored-by: Alan Jowett <alanjo@microsoft.com>  
>Encode BPF instructions to mitigate heap spray attacks (#152)* Encode BPF instructions to mitigate ROP attacks

Signed-off-by: Alan Jowett <alanjo@microsoft.com>

* PR feedback

Signed-off-by: Alan Jowett <alanjo@microsoft.com>

* Fix build break

Signed-off-by: Alan Jowett <alanjo@microsoft.com>  
>Update docs on push to main (#167)* Update docs on push to main

Signed-off-by: Alan Jowett <alanjo@microsoft.com>

* Update the uBPF API docs

Signed-off-by: Alan Jowett <alanjo@microsoft.com>

* Fix repo reference

Signed-off-by: Alan Jowett <alanjo@microsoft.com>

* Add landing page

Signed-off-by: Alan Jowett <alanjo@microsoft.com>

* Update landing page

Signed-off-by: Alan Jowett <alanjo@microsoft.com>

Signed-off-by: Alan Jowett <alanjo@microsoft.com>  
>Merge pull request #128 from Alan-Jowett/issue120Document CMake building procedures  
>Document how to build uBPF with CMakeSigned-off-by: Alan Jowett <alanjo@microsoft.com>  
>Add support for EBPF_CLS_JMP32 JIT and interpret (#166)* Add support for EBPF_CLS_JMP32 x64 JIT and interpret

Signed-off-by: Alan Jowett <alanjo@microsoft.com>

* Attempt JIT arm64 changes for EBPF_CLS_JMP32

Signed-off-by: Alan Jowett <alanjo@microsoft.com>

* Fix Windows path to test files

Signed-off-by: Alan Jowett <alanjo@microsoft.com>

* Add support for jmp32 with imm

Signed-off-by: Alan Jowett <alanjo@microsoft.com>

* All jmp32 ops pass on arm64

Signed-off-by: Alan Jowett <alanjo@microsoft.com>

* Rollback unintended changes

Signed-off-by: Alan Jowett <alanjo@microsoft.com>  
- - - - - - - - - - - - - - - - - - - - - - - - - - - 


2022-09  
Contributor(s):  
Alan Jowett  
>Merge pull request #116 from Alan-Jowett/issue115uBPF behavior around division and modulus is non-conformant  
>Handle division and module by zeroSigned-off-by: Alan Jowett <alanjo@microsoft.com>  
>PR feedback - add tests additional testsSigned-off-by: Alan Jowett <alan.jowett@microsoft.com>  
- - - - - - - - - - - - - - - - - - - - - - - - - - - 


2022-06  
Contributor(s):  
Alan Jowett  
>Merge pull request #109 from trail-of-forks/alessandro/build/add-cmake-supportAdd: CMake, CI, macOS/Windows support, packaging, scan-build  
- - - - - - - - - - - - - - - - - - - - - - - - - - - 


2022-05  
Contributor(s):  
Alan Jowett  
Alessandro Gario  
>cmake: Initial commit  
>Merge pull request #105 from alessandrogario/alessandro/build/add-cmake-supportAdd: CMake, CI, macOS/Windows support, packaging, scan-build  
>Merge pull request #107 from iovisor/revert-105-alessandro/build/add-cmake-supportRevert "Add: CMake, CI, macOS/Windows support, packaging, scan-build"  
>Revert "Add: CMake, CI, macOS/Windows support, packaging, scan-build"  
- - - - - - - - - - - - - - - - - - - - - - - - - - - 


2022-04  
Contributor(s):  
Alan Jowett  
>Merge pull request #36 from jpsamaroo/muslAdded musl support  
>Merge pull request #99 from Linaro/enable-arm64-jitImplement and enable Arm64 JIT  
>Merge pull request #98 from Linaro/fix-asan-issuesFix Address Sanitizer failures  
>Merge pull request #32 from iomartin/masterExpose VM registers  
>Merge pull request #97 from Linaro/enable-null-jitEnable ubpf on platforms with no supported JIT  
- - - - - - - - - - - - - - - - - - - - - - - - - - - 


2022-03  
Contributor(s):  
Matthew Gretton-Dann  
>Fix address sanitizer failures.  
>Add initial Arm64 JIT implementationThis adds initial implementation of the Arm64 JIT.  
>Update README.md with Arm64 support.  
>Enable Arm64 JIT testing  
- - - - - - - - - - - - - - - - - - - - - - - - - - - 


2022-02  
Contributor(s):  
Matthew Gretton-Dann  
>Separate out JITting from interpretingThis patch separates out the JITter from the interpreter.  It adds a"null" JIT which just errors out.After this patch is applied it is possible to build on non-x86-64platforms and run the interpreter without worrying about the JIT.This is achieved by adding a translate function-pointer member tothe ubpf_vm struct. ubpf_create() then sets the pointer up to thecorrect JIT.  Finally ubpf_translate() now delegates to that functionpointer.To enable code reuse some common code from ubpf_jit_x86_64.c is movedinto a new file ubpf_jit.c.Also what was ubpf_translate() in ubpf_jit_x86_64.c is renmaedubpf_translate_x86_64.c.The build process assumes that all backends can be compiled on allplatforms.  It then relies on the linker to not link in unused backends.The code also assumes that only the JIT backend targeting the platformthe code is run on will is needed.Finally, the testing infrastructure is updated to support non-x86-64platforms.  
- - - - - - - - - - - - - - - - - - - - - - - - - - - 


2021-11  
Contributor(s):  
Alan Jowett  
>Add support for string tableSigned-off-by: Alan Jowett <alanjo@microsoft.com>  
>Merge pull request #95 from Alan-Jowett/issue94Make divide by zero handler address independent  
- - - - - - - - - - - - - - - - - - - - - - - - - - - 


2021-10  
Contributor(s):  
Alan Jowett  
Martin Oliveira  
>vm/inc: include stdio.hThe introduction of ubpf_set_error_print() breaks using ubpf as anexternal library.For example, the simple program:    #include <ubpf.h>    int main()    {        return 0;    }Fails to compile with the following (gcc 8.4.0, Ubuntu 18.04):    In file included from a.c:1:    /usr/local/include/ubpf.h:54:67: error: unknown type name ‘FILE’     void ubpf_set_error_print(struct ubpf_vm *vm, int (*error_printf)(FILE* stream, const char* format, ...));                                                                       ^~~~    /usr/local/include/ubpf.h:54:67: note: ‘FILE’ is defined in header ‘<stdio.h>’; did you forget to ‘#include <stdio.h>’?    /usr/local/include/ubpf.h:23:1:    +#include <stdio.h>    /usr/local/include/ubpf.h:54:67:     void ubpf_set_error_print(struct ubpf_vm *vm, int (*error_printf)(FILE* stream, const char* format, ...));To fix it, simply include stdio.h.Fixes: d2c7bdc2bfc4 ("Minimal set of changes required for ubpf to work on Windows.")  
>Merge pull request #91 from iomartin/includevm/inc: include stdio.h  
>Merge pull request #63 from iomartin/unloadvm: introduce ubpf_unload_code()  
- - - - - - - - - - - - - - - - - - - - - - - - - - - 


2021-08  
Contributor(s):  
Alan Jowett  
Rich Lane  
>ubpf on Windows x64 doesn't handle extension functions with 5 parametersWindows x64 ABI passes the 5th parameter on the stack and also assumes there are 4 registers worth of space as [home register space](https://docs.microsoft.com/en-us/cpp/build/stack-usage?view=msvc-160).To fix this uBPF needs to do the following:1) Always push R5 to the stack.2) Allocate space on the stack for R1, R2, R3, and R4 prior to the call.3) Free space on stack after the call.Resolves: #85Signed-off-by: Alan Jowett <alan.jowett@microsoft.com>  
>Merge pull request #88 from Alan-Jowett/issue87Implement unwind on success semantics to support bpf_tail_call.

bpf_tail_call has special semantics. If the call returns success, then ubpf needs to store the return value and unwind the stack so to the caller.

Resolves: #87 

Signed-off-by: Alan Jowett Alan.Jowett@microsoft.com  
>Merge pull request #86 from Alan-Jowett/issue85Fix handling of helpers with 5 parameters on Windows  
>Implement unwind on success semanticsAdd tests for unwind on success semanticsSigned-off-by: Alan Jowett <Alan.Jowett@microsoft.com>  
- - - - - - - - - - - - - - - - - - - - - - - - - - - 


2021-06  
Contributor(s):  
Alan Jowett  
Rich Lane  
>PR feedbackSigned-off-by: Alan Jowett <alan.jowett@microsoft.com>  
>ubpf_exec should separate errors returned from the return valueSigned-off-by: Alan Jowett <alan.jowett@microsoft.com>  
>Merge pull request #78 from Alan-Jowett/issue77Fix register mapping to avoid volatile registers and issues with R12  
>Merge pull request #80 from Alan-Jowett/issue79ubpf_exec should separate errors returned from the return value  
>Tweak register mappingSigned-off-by: Alan Jowett <alan.jowett@microsoft.com>  
>Fix register mapping to avoid volatile registers and issues with R12Signed-off-by: Alan Jowett <alan.jowett@microsoft.com>  
- - - - - - - - - - - - - - - - - - - - - - - - - - - 


2021-05  
Contributor(s):  
Rich Lane  
Niclas Hedam  
>Increasing stack size to common consensus of 512  
>Merge pull request #75 from ITU-DASYALab/feature/stack-512Increasing stack size to common consensus of 512  
>Merge pull request #58 from sbates130272/mem_lengthubpf_vm: Add mem_len via R2 into uBPF VM  
- - - - - - - - - - - - - - - - - - - - - - - - - - - 


2021-04  
Contributor(s):  
Martin Oliveira  
>tests: add tests for VM reuseWe add a couple of options to vm/test.c that allow for testing for VMreuse, as well as corresponding tests.  
>vm: introduce ubpf_unload_code()It is currently not possible to run two different programs on the sameVM, as it will fail during the ubpf_load() of the second program.This function allows unloading a program so that we can reuse the VM.  
- - - - - - - - - - - - - - - - - - - - - - - - - - - 


2020-09  
Contributor(s):  
Julian P Samaroo  
>Added memfrob impl. for musl  
>Added endian.h header for musl  
- - - - - - - - - - - - - - - - - - - - - - - - - - - 


2019-02  
Contributor(s):  
Martin Ichilevici de Oliveira  
>Expose VM registers.This can be useful to:- Inspect registers after program execution.- Determine where registers should be stored.Signed-off-by: Martin Ichilevici de Oliveira <martin.i.oliveira@gmail.com>  
- - - - - - - - - - - - - - - - - - - - - - - - - - - 


2018-11  
Contributor(s):  
ygrek  
>ubpf_vm: initialize R2 with data lengthIt is useful for programs to be able to operate based on the lengthofthe input data passed in to it. Pass in this length via the R2register.[cherry-pick of b7caed9 with some modifications to commit message]Fixes #57.  
- - - - - - - - - - - - - - - - - - - - - - - - - - - 

