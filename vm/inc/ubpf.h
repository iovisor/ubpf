/*
 * Copyright 2015 Big Switch Networks, Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef UBPF_H
#define UBPF_H

#ifdef __cplusplus
extern "C" {
#endif

#include <ubpf_config.h>

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/**
 * @brief Default maximum number of instructions that a program can contain.
 */
#if !defined(UBPF_MAX_INSTS)
#define UBPF_MAX_INSTS 65536
#endif

/**
 * @brief Default stack size for the VM.
 */
#if !defined(UBPF_STACK_SIZE)
#define UBPF_STACK_SIZE 512
#endif

/**
 * @brief Opaque type for a the uBPF VM.
 */
struct ubpf_vm;

/**
 * @brief Opaque type for a uBPF JIT compiled function.
 */
typedef uint64_t (*ubpf_jit_fn)(void* mem, size_t mem_len);

/**
 * @brief Create a new uBPF VM.
 *
 * @return A pointer to the new VM, or NULL on failure.
 */
struct ubpf_vm*
ubpf_create(void);

/**
 * @brief Free a uBPF VM.
 *
 * @param[in] vm The VM to free.
 */
void
ubpf_destroy(struct ubpf_vm* vm);

/**
 * @brief Enable / disable bounds_check. Bounds check is enabled by default, but it may be too restrictive.
 *
 * @param[in] vm The VM to enable / disable bounds check on.
 * @param[in] enable Enable bounds check if true, disable if false.
 * @retval true Bounds check was previously enabled.
 */
bool
ubpf_toggle_bounds_check(struct ubpf_vm* vm, bool enable);

/**
 * @brief Set the function to be invoked if the program hits a fatal error.
 *
 * @param[in] vm The VM to set the error function on.
 * @param[in] error_printf The function to be invoked on fatal error.
 */
void
ubpf_set_error_print(struct ubpf_vm* vm, int (*error_printf)(FILE* stream, const char* format, ...));

/**
 * @brief Register an external function.
 * The immediate field of a CALL instruction is an index into an array of
 * functions registered by the user. This API associates a function with
 * an index.
 *
 * @param[in] vm The VM to register the function on.
 * @param[in] index The index to register the function at.
 * @param[in] name The human readable name of the function.
 * @param[in] fn The function to register.
 * @retval 0 Success.
 * @retval -1 Failure.
 */
int
ubpf_register(struct ubpf_vm* vm, unsigned int index, const char* name, void* fn);

/**
 * @brief Load code into a VM.
 * This must be done before calling ubpf_exec or ubpf_compile and after
 * registering all functions.
 *
 * 'code' should point to eBPF bytecodes and 'code_len' should be the size in
 * bytes of that buffer.
 *
 * @param[in] vm The VM to load the code into.
 * @param[in] code The eBPF bytecodes to load.
 * @param[in] code_len The length of the eBPF bytecodes.
 * @param[out] errmsg The error message, if any. This should be freed by the caller.
 * @retval 0 Success.
 * @retval -1 Failure.
 */
int
ubpf_load(struct ubpf_vm* vm, const void* code, uint32_t code_len, char** errmsg);

/*
 * Unload code from a VM
 *
 * This must be done before calling ubpf_load or ubpf_load_elf, except for the
 * first time those functions are called. It clears the VM instructions to
 * allow for new code to be loaded.
 *
 * It does not unregister any external functions.
 */

/**
 * @brief Unload code from a VM.
 *
 * The VM must be reloaded with code before calling ubpf_exec or ubpf_compile.
 *
 * @param[in] vm The VM to unload the code from.
 */
void
ubpf_unload_code(struct ubpf_vm* vm);

#if defined(UBPF_HAS_ELF_H)
/**
 * @brief Load code from an ELF file.

 * This must be done before calling ubpf_exec or ubpf_compile and after
 * registering all functions.
 *
 * 'elf' should point to a copy of an ELF file in memory and 'elf_len' should
 * be the size in bytes of that buffer.
 *
 * The ELF file must be 64-bit little-endian with a single text section
 * containing the eBPF bytecodes. This is compatible with the output of
 * Clang.
 *
 * @param[in] vm The VM to load the code into.
 * @param[in] elf A pointer to a copy of an ELF file in memory.
 * @param[in] elf_len The size of the ELF file.
 * @param[out] errmsg The error message, if any. This should be freed by the caller.
 * @retval 0 Success.
 * @retval -1 Failure.
 */
int
ubpf_load_elf(struct ubpf_vm* vm, const void* elf, size_t elf_len, char** errmsg);
#endif

/**
 * @brief Execute a BPF program in the VM using the interpreter.
 *
 * A program must be loaded into the VM and all external functions must be
 * registered before calling this function.
 *
 * @param[in] vm The VM to execute the program in.
 * @param[in] mem The memory to pass to the program.
 * @param[in] mem_len The length of the memory.
 * @param[in] bpf_return_value The value of the r0 register when the program exits.
 * @retval 0 Success.
 * @retval -1 Failure.
 */
int
ubpf_exec(const struct ubpf_vm* vm, void* mem, size_t mem_len, uint64_t* bpf_return_value);

/**
 * @brief Compile a BPF program in the VM to native code.
 *
 * A program must be loaded into the VM and all external functions must be
 * registered before calling this function.
 *
 * @param[in] vm The VM to compile the program in.
 * @param[out] errmsg The error message, if any. This should be freed by the caller.
 * @return ubpf_jit_fn A pointer to the compiled program, or NULL on failure.
 */
ubpf_jit_fn
ubpf_compile(struct ubpf_vm* vm, char** errmsg);

/*
 * Translate the eBPF byte code to x64 machine code, store in buffer, and
 * write the resulting count of bytes to size.
 *
 * This must be called after registering all functions.
 *
 * Returns 0 on success, -1 on error. In case of error a pointer to the error
 * message will be stored in 'errmsg' and should be freed by the caller.
 */

/**
 * @brief Translate the eBPF byte code to x64 machine code.
 *
 * A program must be loaded into the VM and all external functions must be
 * registered before calling this function.
 *
 * @param[in] vm The VM to translate the program in.
 * @param[out] buffer The buffer to store the translated code in.
 * @param[in] size The size of the buffer.
 * @param[out] errmsg The error message, if any. This should be freed by the caller.
 * @retval 0 Success.
 * @retval -1 Failure.
 */
int
ubpf_translate(struct ubpf_vm* vm, uint8_t* buffer, size_t* size, char** errmsg);

/**
 * @brief Instruct the uBPF runtime to apply unwind-on-success semantics to a helper function.
 * If the function returns 0, the uBPF runtime will end execution of
 * the eBPF program and immediately return control to the caller. This is used
 * for implementing function like the "bpf_tail_call" helper.
 *
 * @param[in] vm The VM to set the unwind helper in.
 * @param[in] idx Index of the helper function to unwind on success.
 * @retval 0 Success.
 * @retval -1 Failure.
 */
int
ubpf_set_unwind_function_index(struct ubpf_vm* vm, unsigned int idx);

/**
 * @brief Override the storage location for the BPF registers in the VM.
 *
 * @param[in] vm The VM to set the register storage in.
 * @param[in] regs The register storage.
 */
void
ubpf_set_registers(struct ubpf_vm* vm, uint64_t* regs);

/**
 * @brief Retrieve the storage location for the BPF registers in the VM.
 *
 * @param[in] vm The VM to get the register storage from.
 * @return uint64_t* A pointer to the register storage.
 */
uint64_t*
ubpf_get_registers(const struct ubpf_vm* vm);

/**
 * @brief Optional secret to improve ROP protection.
 *
 * @param[in] vm The VM to set the secret for.
 * @param[in] secret Optional secret to improve ROP protection.
 * Returns 0 on success, -1 on error (e.g. if the secret is set after
 * the instructions are loaded).
 */
int
ubpf_set_pointer_secret(struct ubpf_vm* vm, uint64_t secret);

#ifdef __cplusplus
}
#endif

#endif
