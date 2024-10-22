// Copyright (c) uBPF contributors
// SPDX-License-Identifier: MIT

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <iostream>
#include <memory>
#include <vector>
#include <set>
#include <string>
#include <sstream>

#include "libfuzzer_config.h"

#include "asm_unmarshal.hpp"
#include "crab_verifier.hpp"
#include "platform.hpp"

extern "C"
{
#define ebpf_inst ebpf_inst_ubpf
#include "ebpf.h"
#include "ubpf.h"
#undef ebpf_inst
}

#include "test_helpers.h"
#include <cassert>

#if defined(_MSC_VER)
#if defined(DEBUG)
#pragma comment(lib, "clang_rt.fuzzer_MDd-x86_64.lib")
#pragma comment(lib, "libsancov.lib")
#else
#pragma comment(lib, "clang_rt.fuzzer_MD-x86_64.lib")
#pragma comment(lib, "libsancov.lib")
#endif
#endif

/**
 * @brief Class to read the options from the environment and provide them to
 * the fuzzer.
 */
class _ubpf_fuzzer_options
{
public:
    _ubpf_fuzzer_options() {
        for (auto& [key, value] : option) {
            const char* env = std::getenv(key.c_str());
            if (env != nullptr) {
                value = std::stoi(env) != 0;
            }
        }
    }

    bool get(const std::string& key) const {
        return option.at(key);
    }

private:
  std::map<std::string, bool> option{
      // Cheap options enabled by default.
      {"UBPF_FUZZER_JIT", true},         ///< Enable JIT compilation.
      {"UBPF_FUZZER_INTERPRETER", true}, ///< Enable interpreter execution.
      {"UBPF_FUZZER_VERIFY_BYTE_CODE",
       true}, ///< Enable a verifier pass before running the byte code. If byte code is verified, then both bounds check
              ///< and undefined behavior failures are fatal.
      // CPU and memory intensive options disabled by default.
      {"UBPF_FUZZER_CONSTRAINT_CHECK", false},      ///< Enable constraint check against the verifier state. Useful for exhaustive
                                                    ///< testing.
      {"UBPF_FUZZER_PRINT_VERIFIER_REPORT", false}, ///< Print verifier report. Useful for debugging.
      {"UBPF_FUZZER_PRINT_EXECUTION_TRACE", false}, ///< Print execution trace, with register state at each step. Useful for
                                                    ///< debugging.
  };
} g_ubpf_fuzzer_options;


std::string g_verifier_report;

/**
 * @brief Context structure passed to the BPF program. Modeled after the context structure used by XDP.
 */
typedef struct _ubpf_context
{
    uint64_t data;
    uint64_t data_end;
    uint64_t stack_start;
    uint64_t stack_end;
} ubpf_context_t;

/**
 * @brief Descriptor for the context structure. This is used by the verifier to determine the layout of the context
 * structure in memory.
 */
ebpf_context_descriptor_t g_ebpf_context_descriptor_ubpf = {
    .size = sizeof(ubpf_context_t),
    .data = offsetof(ubpf_context_t, data),
    .end = offsetof(ubpf_context_t, data_end),
    .meta = -1,
};

/**
 * @brief Description of the program type. This is used by the verifier to determine what context structure to use as
 * well as the helper functions that are available.
 */
EbpfProgramType g_ubpf_program_type = {
    .name = "ubpf",
    .context_descriptor = &g_ebpf_context_descriptor_ubpf,
    .platform_specific_data = 0,
    .section_prefixes = {},
    .is_privileged = false,
};

/**
 * @brief This function is called by the verifier when parsing an ELF file to determine the type of the program being
 * loaded based on the section and path.
 *
 * @param[in] section The section name of the program.
 * @param[in] path The path to the ELF file.
 * @return The type of the program.
 */
EbpfProgramType
ubpf_get_program_type(const std::string& section, const std::string& path)
{
    UNREFERENCED_PARAMETER(section);
    UNREFERENCED_PARAMETER(path);
    return g_ubpf_program_type;
}

/***
 * @brief This function is called by the verifier to determine the type of a map given the platform specific type.
 *
 * @param[in] platform_specific_type The platform specific type of the map.
 * @return The type of the map.
 */
EbpfMapType
ubpf_get_map_type(uint32_t platform_specific_type)
{
    // Once the fuzzer supports maps, this function should be implemented to return metadata about the map, primarily
    // the key and value size.
    UNREFERENCED_PARAMETER(platform_specific_type);
    return {};
}

/**
 * @brief This function is called by the verifier to determine the prototype of a helper function given the helper
 * function number.
 *
 * @param[in] n The helper function number.
 * @return The prototype of the helper function.
 */
EbpfHelperPrototype
ubpf_get_helper_prototype(int32_t n)
{
    // Once the fuzzer supports helper functions, this function should be implemented to return metadata about the
    // helper function.
    UNREFERENCED_PARAMETER(n);
    return {};
}

/**
 * @brief This function is called by the verifier to determine whether a helper function is usable given the helper
 * function number.
 *
 * @param[in] n The helper function number.
 * @retval true The helper function is usable.
 * @retval false The helper function is not usable.
 */
bool
ubpf_is_helper_usable(int32_t n)
{
    // Once the fuzzer supports helper functions, this function should be implemented to return whether the helper
    // function is usable.
    UNREFERENCED_PARAMETER(n);
    return false;
}

/**
 * @brief This function is called by the verifier to parse the maps section of the ELF file (if any).
 *
 * @param[in,out] map_descriptors The map descriptors to populate.
 * @param[in] data The data in the maps section.
 * @param[in] map_record_size The size of each map record.
 * @param[in] map_count The number of maps in the maps section.
 * @param[in] platform The platform specific data.
 * @param[in] options Options for the verifier.
 */
void
ubpf_parse_maps_section(
    std::vector<EbpfMapDescriptor>& map_descriptors,
    const char* data,
    size_t map_record_size,
    int map_count,
    const struct ebpf_platform_t* platform,
    ebpf_verifier_options_t options)
{
    // Once the fuzzer supports maps, this function should be implemented to parse the maps section of the ELF file (if
    // any).
    UNREFERENCED_PARAMETER(map_descriptors);
    UNREFERENCED_PARAMETER(data);
    UNREFERENCED_PARAMETER(map_record_size);
    UNREFERENCED_PARAMETER(map_count);
    UNREFERENCED_PARAMETER(platform);
    UNREFERENCED_PARAMETER(options);
    throw std::runtime_error("parse_maps_section not implemented");
}

/**
 * @brief Given a map descriptor, resolve any inner map references to other maps.
 *
 * @param[in,out] map_descriptors The map descriptors to resolve.
 */
void
ubpf_resolve_inner_map_references(std::vector<EbpfMapDescriptor>& map_descriptors)
{
    // Once the fuzzer supports maps, this function should be implemented to resolve inner map references.
    UNREFERENCED_PARAMETER(map_descriptors);
    throw std::runtime_error("resolve_inner_map_references not implemented");
}

/**
 * @brief The function is called by the verifier to get the map descriptor for a given map file descriptor.
 *
 * @param[in] map_fd The map file descriptor.
 * @return The map descriptor.
 */
EbpfMapDescriptor&
ubpf_get_map_descriptor(int map_fd)
{
    // Once the fuzzer supports maps, this function should be implemented to return the map descriptor for the given map
    // file descriptor.
    UNREFERENCED_PARAMETER(map_fd);
    throw std::runtime_error("get_map_descriptor not implemented");
}

/**
 * @brief The platform abstraction for the verifier to call into the uBPF fuzzer platform.
 */
ebpf_platform_t g_ebpf_platform_ubpf_fuzzer = {
    .get_program_type = ubpf_get_program_type,
    .get_helper_prototype = ubpf_get_helper_prototype,
    .is_helper_usable = ubpf_is_helper_usable,
    .map_record_size = 0,
    .parse_maps_section = ubpf_parse_maps_section,
    .get_map_descriptor = ubpf_get_map_descriptor,
    .get_map_type = ubpf_get_map_type,
    .resolve_inner_map_references = ubpf_resolve_inner_map_references,
    .supported_conformance_groups = bpf_conformance_groups_t::default_groups,
};

/**
 * @brief Dispatcher for the helper functions.
 *
 * @param[in] p0 First parameter to the helper function.
 * @param[in] p1 Second parameter to the helper function.
 * @param[in] p2 Third parameter to the helper function.
 * @param[in] p3 Fourth parameter to the helper function.
 * @param[in] p4 Fifth parameter to the helper function.
 * @param[in] idx Index of the helper function to call.
 * @param[in] cookie Cookie to pass to the helper function.
 * @return Value returned by the helper function.
 */
uint64_t
test_helpers_dispatcher(uint64_t p0, uint64_t p1, uint64_t p2, uint64_t p3, uint64_t p4, unsigned int idx, void* cookie)
{
    UNREFERENCED_PARAMETER(cookie);
    return helper_functions[idx](p0, p1, p2, p3, p4);
}

/**
 * @brief Function to validate the helper function index.
 *
 * @param[in] idx Helper function index.
 * @param[in] vm The VM instance.
 * @retval true The helper function index is valid.
 * @retval false The helper function index is invalid.
 */
bool
test_helpers_validator(unsigned int idx, const struct ubpf_vm* vm)
{
    UNREFERENCED_PARAMETER(vm);
    return helper_functions.contains(idx);
}

extern "C" int
LLVMFuzzerTestOneInput(const uint8_t* data, std::size_t size);

std::string g_error_message;

/**
 * @brief Capture the output of printf to a string.
 *
 * @param[in,out] stream The stream to write to.
 * @param[in] format The format string.
 * @param[in] ... The arguments to the format string.
 *
 * @return The number of characters written.
 */
int capture_printf(FILE* stream, const char* format, ...)
{
    // Format the message and append it to g_error_message.

    UNREFERENCED_PARAMETER(stream);

    va_list args;
    va_start(args, format);
    char buffer[1024];
    int ret = vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    if (ret < 0) {
        return ret;
    }

    g_error_message += buffer;

    return ret;
}

/**
 * @brief Invoke the verifier to verify the given BPF program.
 *
 * @param[in] program_code The program byte code to verify.
 * @retval true The program is safe to run.
 * @retval false The program might be unsafe to run. Note: The verifier is conservative and may reject safe programs.
 */
bool
verify_bpf_byte_code(const std::vector<uint8_t>& program_code)
try {
    std::ostringstream error;
    auto instruction_array = reinterpret_cast<const ebpf_inst*>(program_code.data());
    size_t instruction_count = program_code.size() / sizeof(ebpf_inst);
    const ebpf_platform_t* platform = &g_ebpf_platform_ubpf_fuzzer;
    std::vector<ebpf_inst> instructions{instruction_array, instruction_array + instruction_count};
    program_info info{
        .platform = platform,
        .type = g_ubpf_program_type,
    };
    std::string section;
    std::string file;
    raw_program raw_prog{file, section, 0, {}, instructions, info};

    // Unpack the program into a sequence of instructions that the verifier can understand.
    std::variant<InstructionSeq, std::string> prog_or_error = unmarshal(raw_prog);
    if (!std::holds_alternative<InstructionSeq>(prog_or_error)) {
        return false;
    }

    // Extract the program instructions.
    InstructionSeq& prog = std::get<InstructionSeq>(prog_or_error);

    // Start with the default verifier options.
    ebpf_verifier_options_t options = ebpf_verifier_default_options;

    // Enable termination checking and pre-invariant storage.
    options.check_termination = true;
    options.print_invariants = g_ubpf_fuzzer_options.get("UBPF_FUZZER_PRINT_VERIFIER_REPORT");
    options.print_failures = g_ubpf_fuzzer_options.get("UBPF_FUZZER_PRINT_VERIFIER_REPORT");
#if defined(HAVE_EBPF_VERIFIER_CHECK_CONSTRAINTS_AT_LABEL)
    options.store_pre_invariants = g_ubpf_fuzzer_options.get("UBPF_FUZZER_CONSTRAINT_CHECK");
#endif

    // Disable simplification so that the verifier can provide more fine grained invariant information for each
    // instruction.
    options.simplify = false;

    ebpf_verifier_stats_t stats;

    std::ostringstream error_stream;

    // Verify the program. This will return false or throw an exception if the program is invalid.
    bool result = ebpf_verify_program(error_stream, prog, raw_prog.info, &options, &stats);
    if (g_ubpf_fuzzer_options.get("UBPF_FUZZER_PRINT_VERIFIER_REPORT")) {
        std::cout << "verifier stats:" << std::endl;
        std::cout << "total_unreachable: " << stats.total_unreachable << std::endl;
        std::cout << "total_warnings: " << stats.total_warnings << std::endl;
        std::cout << "max_loop_count: " << stats.max_loop_count << std::endl;
        std::cout << "result: " << result << std::endl;
        std::cout << error_stream.str() << std::endl;
    }

    return result;
} catch (const std::exception& ex) {
    return false;
}

/**
 * @brief RAII wrapper for the ubpf_vm object.
 */
typedef std::unique_ptr<ubpf_vm, decltype(&ubpf_destroy)> ubpf_vm_ptr;

/**
 * @brief Create a ubpf vm object and load the program code into it.
 *
 * @param[in] program_code The program code to load into the VM.
 * @return A unique pointer to the ubpf_vm object or nullptr if the VM could not be created.
 */
ubpf_vm_ptr
create_ubpf_vm(const std::vector<uint8_t>& program_code)
{
    // Automatically free the VM when it goes out of scope.
    std::unique_ptr<ubpf_vm, decltype(&ubpf_destroy)> vm(ubpf_create(), ubpf_destroy);

    if (vm == nullptr) {
        // Failed to create the VM.
        // This is not interesting, as the fuzzer input is invalid.
        // Do not add it to the corpus.
        return {nullptr, nullptr};
    }

    ubpf_toggle_undefined_behavior_check(vm.get(), true);

    char* error_message = nullptr;

    // Capture any error messages from the uBPF library.
    ubpf_set_error_print(vm.get(), capture_printf);

    if (ubpf_load(vm.get(), program_code.data(), program_code.size(), &error_message) != 0) {
        // The program failed to load, due to a validation error.
        // This is not interesting, as the fuzzer input is invalid.
        // Do not add it to the corpus.
        g_error_message += error_message;
        free(error_message);
        return {nullptr, nullptr};
    }

    // Bounds checking is always active. Instead the behavior is if an out of bounds access is detected, the fuzzing either
    // ignores the error or raises a fatal signal.
    ubpf_toggle_bounds_check(vm.get(), true);

    if (ubpf_register_external_dispatcher(vm.get(), test_helpers_dispatcher, test_helpers_validator) != 0) {
        // Failed to register the external dispatcher.
        // This is not interesting, as the fuzzer input is invalid.
        // Do not add it to the corpus.
        return {nullptr, nullptr};
    }

    if (ubpf_set_instruction_limit(vm.get(), 10000, nullptr) != 0) {
        // Failed to set the instruction limit.
        // This is not interesting, as the fuzzer input is invalid.
        // Do not add it to the corpus.
        return {nullptr, nullptr};
    }

    return vm;
}

/**
 * @brief Classify the given address as packet, context, stack, map, or unknown.
 */
typedef enum class _address_type
{
    Packet,
    Context,
    Stack,
    Map,
    Unknown
} address_type_t;

/**
 * @brief Given a register value, classify it as packet, context, stack, or unknown.
 *
 * @param[in] context Pointer to the context structure.
 * @param[in] register_value Register value to classify.
 * @retval address_type_t::Packet The register value is within the packet data.
 * @retval address_type_t::Context The register value is within the context structure.
 * @retval address_type_t::Stack The register value is within the stack.
 * @retval address_type_t::Unknown The register value is unknown.
 */
address_type_t
ubpf_classify_address(const ubpf_context_t* context, uint64_t register_value)
{
    uintptr_t register_value_ptr = static_cast<uintptr_t>(register_value);
    uintptr_t stack_start = static_cast<uintptr_t>(context->stack_start);
    uintptr_t stack_end = static_cast<uintptr_t>(context->stack_end);
    uintptr_t context_start = reinterpret_cast<uintptr_t>(context);
    uintptr_t context_end = context_start + sizeof(ubpf_context_t);
    uintptr_t packet_start = static_cast<uintptr_t>(context->data);
    uintptr_t packet_end = static_cast<uintptr_t>(context->data_end);

    if (register_value_ptr >= stack_start && register_value_ptr < stack_end) {
        return address_type_t::Stack;
    } else if (register_value_ptr >= context_start && register_value_ptr < context_end) {
        return address_type_t::Context;
    } else if (register_value_ptr >= packet_start && register_value_ptr < packet_end) {
        return address_type_t::Packet;
    } else {
        return address_type_t::Unknown;
    }
}

/**
 * @brief Function invoked prior to executing each instruction in the program.
 *
 * @param[in] context Context passed to the program.
 * @param[in] program_counter The program counter (the index of the instruction to execute).
 * @param[in] registers The register values.
 * @param[in] stack_start The start of the stack.
 * @param[in] stack_length The length of the stack.
 * @param[in] register_mask The set of registers that have been modified since the start of the program.
 * @param[in] stack_mask The set of stack locations that have been modified since the start of the program.
 */
void
ubpf_debug_function(
    void* context,
    int program_counter,
    const uint64_t registers[16],
    const uint8_t* stack_start,
    size_t stack_length,
    uint64_t register_mask,
    const uint8_t* stack_mask)
{
    // Print the program counter and register values.
    if (g_ubpf_fuzzer_options.get("UBPF_FUZZER_PRINT_EXECUTION_TRACE")) {
        std::cout << "Program Counter: " << program_counter << std::endl;
        std::cout << "Registers: ";
        for (int i = 0; i < 10; i++) {
            if ((register_mask & (1 << i)) == 0) {
                continue;
            }
            std::cout << "r" << i << "=" << registers[i] << " ";
        }
        std::cout << std::endl;
    }

    if (g_ubpf_fuzzer_options.get("UBPF_FUZZER_CONSTRAINT_CHECK")) {
#if defined(HAVE_EBPF_VERIFIER_CHECK_CONSTRAINTS_AT_LABEL)
        ubpf_context_t* ubpf_context = reinterpret_cast<ubpf_context_t*>(context);
        UNREFERENCED_PARAMETER(stack_start);
        UNREFERENCED_PARAMETER(stack_length);
        UNREFERENCED_PARAMETER(stack_mask);

        std::string label = std::to_string(program_counter) + ":-1";

        if (program_counter == 0) {
            return;
        }

        // Build set of string constraints from the register values.
        std::set<std::string> constraints;
        for (int i = 0; i < 10; i++) {
            if ((register_mask & (1 << i)) == 0) {
                continue;
            }
            uint64_t reg = registers[i];
            std::string register_name = "r" + std::to_string(i);

            // Given the register value, classify it as packet, context, stack, or unknown and add the appropriate
            // constraint.
            address_type_t type = ubpf_classify_address(ubpf_context, reg);
            switch (type) {
            case address_type_t::Packet:
                constraints.insert(register_name + ".type=packet");
                constraints.insert(register_name + ".packet_offset=" + std::to_string(reg - ubpf_context->data));
                constraints.insert(
                    register_name + ".packet_size=" + std::to_string(ubpf_context->data_end - ubpf_context->data));
                break;

            case address_type_t::Context:
                constraints.insert(register_name + ".type=ctx");
                constraints.insert(
                    register_name + ".ctx_offset=" + std::to_string(reg - reinterpret_cast<uint64_t>(ubpf_context)));
                break;

            case address_type_t::Stack:
                constraints.insert(register_name + ".type=stack");
                constraints.insert(register_name + ".stack_offset=" + std::to_string(reg - ubpf_context->stack_start));
                break;

            case address_type_t::Unknown:
                constraints.insert("r" + std::to_string(i) + ".uvalue=" + std::to_string(registers[i]));
                constraints.insert(
                    "r" + std::to_string(i) + ".svalue=" + std::to_string(static_cast<int64_t>(registers[i])));
                break;
            case address_type_t::Map:
                constraints.insert(register_name + ".type=shared");
                break;
            }
        }

        // Call ebpf_check_constraints_at_label with the set of string constraints at this label.

        std::ostringstream os;

        if (!ebpf_check_constraints_at_label(os, label, constraints)) {
            std::cerr << "Label: " << label << std::endl;
            std::cerr << os.str() << std::endl;
            throw std::runtime_error("ebpf_check_constraints_at_label failed");
        }
#else
        throw std::runtime_error("ebpf_check_constraints_at_label not supported");
        UNREFERENCED_PARAMETER(context);
        UNREFERENCED_PARAMETER(stack_start);
        UNREFERENCED_PARAMETER(stack_length);
        UNREFERENCED_PARAMETER(stack_mask);
#endif
    }
}

/**
 * @brief Helper function to create a ubpf_context_t object from the given memory and stack.
 *
 * @param[in] memory Vector containing the input memory.
 * @param[in] ubpf_stack Vector containing the stack.
 * @return The context object.
 */
ubpf_context_t
ubpf_context_from(std::vector<uint8_t>& memory, std::vector<uint8_t>& ubpf_stack)
{
    ubpf_context_t context;
    context.data = reinterpret_cast<uint64_t>(memory.data());
    context.data_end = context.data + memory.size();
    context.stack_start = reinterpret_cast<uint64_t>(ubpf_stack.data());
    context.stack_end = context.stack_start + ubpf_stack.size();
    return context;
}

/**
 * @brief Function to check if the given address and size are within the bounds of the memory or stack.
 *
 * @param[in] context The context passed to ubpf_register_data_bounds_check.
 * @param[in] addr The address to check.
 * @param[in] size The size of the memory to check.
 * @retval true The address and size are within the bounds of the memory or stack.
 * @retval false The address and size are not within the bounds of the memory or stack.
 */
bool bounds_check(void* context, uint64_t addr, uint64_t size)
{
    ubpf_context_t* ubpf_context = reinterpret_cast<ubpf_context_t*>(context);

    // Check if the lower bound of the address is within the bounds of the memory or stack.
    if (ubpf_classify_address(ubpf_context, addr) == address_type_t::Unknown) {
        std::cerr << "Address out of bounds: " << std::hex << addr << std::endl;
        std::cerr << "Memory start: "  << std::hex << ubpf_context->data << std::endl;
        std::cerr << "Memory end: " << std::hex << ubpf_context->data_end << std::endl;
        std::cerr << "Stack start: " << std::hex << ubpf_context->stack_start << std::endl;
        std::cerr << "Stack end: " << std::hex << ubpf_context->stack_end << std::endl;
        std::cerr << "Context start:" << std::hex << reinterpret_cast<uint64_t>(ubpf_context) << std::endl;
        std::cerr << "Context end:" << std::hex << reinterpret_cast<uint64_t>(ubpf_context) + sizeof(ubpf_context_t) << std::endl;
        return false;
    }

    // Check if the upper bound of the address is within the bounds of the memory or stack.
    if (ubpf_classify_address(ubpf_context, addr + size - 1) == address_type_t::Unknown) {
        std::cerr << "Address out of bounds: " << std::hex << addr << std::endl;
        std::cerr << "Memory start: " << std::hex << ubpf_context->data << std::endl;
        std::cerr << "Memory end: " << std::hex << ubpf_context->data_end << std::endl;
        std::cerr << "Stack start: " << std::hex << ubpf_context->stack_start << std::endl;
        std::cerr << "Stack end: " << std::hex << ubpf_context->stack_end << std::endl;
        std::cerr << "Context start:" << std::hex << reinterpret_cast<uint64_t>(ubpf_context) << std::endl;
        std::cerr << "Context end:" << std::hex << reinterpret_cast<uint64_t>(ubpf_context) + sizeof(ubpf_context_t) << std::endl;
        return false;
    }

    return true;
}

const std::set<std::string> g_error_message_to_ignore{
};

/**
 * @brief Invoke the ubpf interpreter with the given program code and input memory.
 *
 * @param[in] program_code The program code to execute.
 * @param[in,out] memory The input memory to use when executing the program. May be modified by the program.
 * @param[in,out] ubpf_stack The stack to use when executing the program. May be modified by the program.
 * @param[out] interpreter_result The result of the program execution.
 * @retval true The program executed successfully.
 * @retval false The program failed to execute.
 */
bool
call_ubpf_interpreter(
    const std::vector<uint8_t>& program_code,
    std::vector<uint8_t>& memory,
    std::vector<uint8_t>& ubpf_stack,
    uint64_t& interpreter_result)
{
    auto vm = create_ubpf_vm(program_code);
    if (vm == nullptr) {
        // VM creation failed.
        return false;
    }

    ubpf_context_t context = ubpf_context_from(memory, ubpf_stack);

    ubpf_register_debug_fn(vm.get(), &context, ubpf_debug_function);
    ubpf_register_data_bounds_check(vm.get(), &context, bounds_check);

    // Execute the program using the input memory.
    if (ubpf_exec_ex(vm.get(), &context, sizeof(context), &interpreter_result, ubpf_stack.data(), ubpf_stack.size()) != 0) {
        // Check if the error is being suppressed by one of the known error messages regex.
        for (const auto& error_message : g_error_message_to_ignore) {
            if (std::regex_search(g_error_message, std::regex(error_message))) {
                return false;
            }
        }

        // If the byte code was verified, then both bounds check and undefined behavior failures are fatal.
        if (g_ubpf_fuzzer_options.get("UBPF_FUZZER_VERIFY_BYTE_CODE")) {
            throw std::runtime_error("Failed to execute program with error: " + g_error_message);
        }
    }

    // VM execution succeeded.
    return true;
}

/**
 * @brief Execute the given program code using the ubpf JIT.
 *
 * @param[in] program_code The program code to execute.
 * @param[in,out] memory The input memory to use when executing the program. May be modified by the program.
 * @param[in,out] ubpf_stack The stack to use when executing the program. May be modified by the program.
 * @param[out] interpreter_result The result of the program execution.
 * @retval true The program executed successfully.
 * @retval false The program failed to execute.
 */
bool
call_ubpf_jit(
    const std::vector<uint8_t>& program_code,
    std::vector<uint8_t>& memory,
    std::vector<uint8_t>& ubpf_stack,
    uint64_t& jit_result)
{
    auto vm = create_ubpf_vm(program_code);

    ubpf_context_t context = ubpf_context_from(memory, ubpf_stack);

    char* error_message = nullptr;

    if (vm == nullptr) {
        // VM creation failed.
        return false;
    }

    auto fn = ubpf_compile_ex(vm.get(), &error_message, JitMode::ExtendedJitMode);

    if (fn == nullptr) {
        std::string error_message_str = error_message ? error_message : "unknown error";
        free(error_message);
        throw std::runtime_error("Failed to compile program with error: " + error_message_str);
    }

    jit_result = fn(&context, sizeof(context), ubpf_stack.data(), ubpf_stack.size());

    // Compilation succeeded.
    return true;
}

/**
 * @brief Copy the program and memory from the input buffer into separate buffers.
 *
 * @param[in] data The input buffer from the fuzzer.
 * @param[in] size The size of the input buffer.
 * @param[out] program The program code extracted from the input buffer.
 * @param[out] memory The input memory extracted from the input buffer.
 * @retval true The input buffer was successfully split.
 * @retval false The input buffer is malformed.
 */
bool
split_input(const uint8_t* data, std::size_t size, std::vector<uint8_t>& program, std::vector<uint8_t>& memory)
{
    if (size < 4)
        return false;

    uint32_t program_length = *reinterpret_cast<const uint32_t*>(data);
    uint32_t memory_length = size - 4 - program_length;
    const uint8_t* program_start = data + 4;
    const uint8_t* memory_start = data + 4 + program_length;

    if (program_length > size) {
        // The program length is larger than the input size.
        // This is not interesting, as the fuzzer input is invalid.
        return false;
    }

    if (program_length == 0) {
        // The program length is zero.
        // This is not interesting, as the fuzzer input is invalid.
        return false;
    }

    if (program_length + 4u > size) {
        // The program length is larger than the input size.
        // This is not interesting, as the fuzzer input is invalid.
        return false;
    }

    if ((program_length % sizeof(ebpf_inst)) != 0) {
        // The program length needs to be a multiple of sizeof(ebpf_inst_t).
        // This is not interesting, as the fuzzer input is invalid.
        return false;
    }

    // Copy any input memory into a writable buffer.
    if (memory_length > 0) {
        memory.resize(memory_length);
        std::memcpy(memory.data(), memory_start, memory_length);
    }

    program.resize(program_length);
    std::memcpy(program.data(), program_start, program_length);

    return true;
}

/**
 * @brief Accept an input buffer and size.
 *
 * @param[in] data Pointer to the input buffer.
 * @param[in] size Size of the input buffer.
 * @retval -1 The input is invalid
 * @retval 0 The input is valid and processed.
 */
int
LLVMFuzzerTestOneInput(const uint8_t* data, std::size_t size) try
{
    // Assume the fuzzer input is as follows:
    // 32-bit program length
    // program byte
    // test data

    std::vector<uint8_t> program;
    std::vector<uint8_t> memory;
    std::vector<uint8_t> ubpf_stack(3 * 4096);
    g_error_message = "";

    if (!split_input(data, size, program, memory)) {
        // The input is invalid. Not interesting.
        return -1;
    }

    if (g_ubpf_fuzzer_options.get("UBPF_FUZZER_VERIFY_BYTE_CODE")) {
        if (!verify_bpf_byte_code(program)) {
            // The program failed verification.
            return 0;
        }
    }

    uint64_t interpreter_result = 0;
    uint64_t jit_result = 0;

    if (g_ubpf_fuzzer_options.get("UBPF_FUZZER_INTERPRETER")) {
        if (!call_ubpf_interpreter(program, memory, ubpf_stack, interpreter_result)) {
            // Failed to load or execute the program in the interpreter.
            // This is not interesting, as the fuzzer input is invalid.
            return 0;
        }
    }

    if (!split_input(data, size, program, memory)) {
        // The input was successfully split, but failed to split again.
        // This should not happen.
        assert(!"split_input failed");
    }

    if (g_ubpf_fuzzer_options.get("UBPF_FUZZER_JIT")) {
        if (!call_ubpf_jit(program, memory, ubpf_stack, jit_result)) {
            // Failed to load or execute the program in the JIT.
            // This is not interesting, as the fuzzer input is invalid.
            return 0;
        }
    }

    if (g_ubpf_fuzzer_options.get("UBPF_FUZZER_JIT") && g_ubpf_fuzzer_options.get("UBPF_FUZZER_INTERPRETER")) {
        // If interpreter_result is not equal to jit_result, raise a fatal signal
        if (interpreter_result != jit_result) {
            printf("%lx ubpf_stack\n", reinterpret_cast<uintptr_t>(ubpf_stack.data()) + ubpf_stack.size());
            printf("interpreter_result: %lx\n", interpreter_result);
            printf("jit_result: %lx\n", jit_result);
            throw std::runtime_error("interpreter_result != jit_result");
        }
    }

    // Program executed successfully.
    // Add it to the corpus as it may be interesting.
    return 0;
}
catch (const std::exception& ex) {
    std::cerr << "Exception: " << ex.what() << std::endl;
    throw;
}
