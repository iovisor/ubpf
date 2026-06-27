// Copyright (c) uBPF contributors
// SPDX-License-Identifier: Apache-2.0

#include <cstdint>
#include <cstring>
#include <iostream>
#include <memory>
#include <vector>

extern "C"
{
#include "ubpf.h"
}

#include "ubpf_custom_test_support.h"

// The ELF loader API (ubpf_load_elf_ex) is only declared when uBPF is built with
// <elf.h> support, which is not the case on Windows. Skip the test there.
#if defined(UBPF_HAS_ELF_H)

// Build a minimal ET_REL BPF object in memory:
//   section "prog" (PROGBITS, ALLOC|EXECINSTR):
//     0x00 callee: r0 = 7 ; exit
//     0x10 entry : call callee ; exit   (PC-relative imm = -3, NO relocation)
//   one combined string table (section names + symbol names)
//   symbol table lists entry (st_value 0x10) BEFORE callee (st_value 0x00)
// main-function = "entry".
static std::vector<uint8_t>
build_reorder_elf()
{
    auto u16 = [](std::vector<uint8_t>& v, uint16_t x) {
        v.push_back(x & 0xff); v.push_back((x >> 8) & 0xff);
    };
    auto u32 = [](std::vector<uint8_t>& v, uint32_t x) {
        for (int i = 0; i < 4; i++) v.push_back((x >> (8 * i)) & 0xff);
    };
    auto u64 = [](std::vector<uint8_t>& v, uint64_t x) {
        for (int i = 0; i < 8; i++) v.push_back((x >> (8 * i)) & 0xff);
    };
    auto insn = [](std::vector<uint8_t>& v, uint8_t op, uint8_t dst, uint8_t src,
                   int16_t off, int32_t imm) {
        v.push_back(op);
        v.push_back((uint8_t)((src << 4) | (dst & 0xf)));
        v.push_back(off & 0xff); v.push_back((off >> 8) & 0xff);
        for (int i = 0; i < 4; i++) v.push_back(((uint32_t)imm >> (8 * i)) & 0xff);
    };

    // prog section bytes
    std::vector<uint8_t> text;
    insn(text, 0xb7, 0, 0, 0, 7);   // callee: r0 = 7
    insn(text, 0x95, 0, 0, 0, 0);   // callee: exit
    insn(text, 0x85, 0, 1, 0, -3);  // entry : call callee (PC-relative)
    insn(text, 0x95, 0, 0, 0, 0);   // entry : exit

    // combined string table
    std::string strt;
    strt.push_back('\0');
    auto add_str = [&](const char* s) { size_t off = strt.size(); strt += s; strt.push_back('\0'); return (uint32_t)off; };
    uint32_t n_prog = add_str("prog");
    uint32_t n_strtab = add_str(".strtab");
    uint32_t n_symtab = add_str(".symtab");
    uint32_t n_callee = add_str("callee");
    uint32_t n_entry = add_str("entry");

    // symbol table: null, entry (global func, off 0x10), callee (local func, off 0x00)
    const uint8_t PROG = 1;
    std::vector<uint8_t> sym;
    auto add_sym = [&](uint32_t name, uint8_t info, uint16_t shndx, uint64_t val, uint64_t size) {
        u32(sym, name); sym.push_back(info); sym.push_back(0); u16(sym, shndx); u64(sym, val); u64(sym, size);
    };
    add_sym(0, 0, 0, 0, 0);
    add_sym(n_entry,  (1 << 4) | 2, PROG, 0x10, 16);  // STB_GLOBAL|STT_FUNC
    add_sym(n_callee, (0 << 4) | 2, PROG, 0x00, 16);  // STB_LOCAL|STT_FUNC

    // offsets
    const uint64_t ehsize = 64, shsize = 64, nsh = 4;
    uint64_t off = ehsize;
    uint64_t text_off = off; off += text.size();
    uint64_t strt_off = off; off += strt.size();
    uint64_t sym_off = off; off += sym.size();
    uint64_t pad = (8 - (off % 8)) % 8; off += pad;
    uint64_t shoff = off;

    std::vector<uint8_t> elf;
    // e_ident
    elf.push_back(0x7f); elf.push_back('E'); elf.push_back('L'); elf.push_back('F');
    elf.push_back(2); elf.push_back(1); elf.push_back(1); elf.push_back(0);
    for (int i = 0; i < 8; i++) elf.push_back(0);
    u16(elf, 1);     // e_type ET_REL
    u16(elf, 247);   // e_machine EM_BPF
    u32(elf, 1);     // e_version
    u64(elf, 0);     // e_entry
    u64(elf, 0);     // e_phoff
    u64(elf, shoff); // e_shoff
    u32(elf, 0);     // e_flags
    u16(elf, ehsize);// e_ehsize
    u16(elf, 0); u16(elf, 0);        // phentsize, phnum
    u16(elf, shsize); u16(elf, nsh); // shentsize, shnum
    u16(elf, 2);     // e_shstrndx -> .strtab (index 2)

    elf.insert(elf.end(), text.begin(), text.end());
    elf.insert(elf.end(), strt.begin(), strt.end());
    elf.insert(elf.end(), sym.begin(), sym.end());
    for (uint64_t i = 0; i < pad; i++) elf.push_back(0);

    auto add_shdr = [&](uint32_t name, uint32_t type, uint64_t flags, uint64_t addr,
                        uint64_t offset, uint64_t size, uint32_t link, uint32_t info,
                        uint64_t align, uint64_t entsize) {
        u32(elf, name); u32(elf, type); u64(elf, flags); u64(elf, addr);
        u64(elf, offset); u64(elf, size); u32(elf, link); u32(elf, info);
        u64(elf, align); u64(elf, entsize);
    };
    add_shdr(0, 0, 0, 0, 0, 0, 0, 0, 0, 0);                                  // NULL
    add_shdr(n_prog, 1, 0x2 | 0x4, 0, text_off, text.size(), 0, 0, 8, 0);    // prog PROGBITS ALLOC|EXEC
    add_shdr(n_strtab, 3, 0, 0, strt_off, strt.size(), 0, 0, 1, 0);          // .strtab STRTAB
    add_shdr(n_symtab, 2, 0, 0, sym_off, sym.size(), 2, 1, 8, 24);           // .symtab SYMTAB link=.strtab

    return elf;
}

int
main(int, char**)
{
    std::vector<uint8_t> elf = build_reorder_elf();

    std::unique_ptr<ubpf_vm, decltype(&ubpf_destroy)> vm(ubpf_create(), ubpf_destroy);
    if (!vm) {
        std::cerr << "Failed to create VM\n";
        return 1;
    }

    char* errmsg = nullptr;
    int rv = ubpf_load_elf_ex(vm.get(), elf.data(), elf.size(), "entry", &errmsg);
    if (rv < 0) {
        std::cerr << "Failed to load ELF: " << (errmsg ? errmsg : "(null)") << "\n";
        free(errmsg);
        return 1;
    }

    uint64_t result = 0;
    if (ubpf_exec(vm.get(), nullptr, 0, &result) < 0) {
        std::cerr << "Failed to execute program\n";
        return 1;
    }

    if (result != 7) {
        std::cerr << "Expected 0x7, got 0x" << std::hex << result << "\n";
        return 1;
    }

    std::cout << "PASS\n";
    return 0;
}

#else // !UBPF_HAS_ELF_H

int
main(int, char**)
{
    std::cout << "SKIP: ELF loader not built (no <elf.h> support)\n";
    return 0;
}

#endif // UBPF_HAS_ELF_H
