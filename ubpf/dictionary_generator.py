# Copyright (c) uBPF contributors
# SPDX-License-Identifier: MIT

# Generate a dictionary file of all legal BPF instructions, with immediate values and offsets set to zero.
# Each instruction is written to the output stream in the form of a quoted 8-byte sequence of hex, with each byte prefixed wit\x with no spaces.

import struct
import disassembler

Inst = struct.Struct("BBHI")

CLASSES = {
    0: "ld",
    1: "ldx",
    2: "st",
    3: "stx",
    4: "alu",
    5: "jmp",
    6: "jmp32",
    7: "alu64",
}

ALU_OPCODES = {
    0: 'add',
    1: 'sub',
    2: 'mul',
    3: 'div',
    4: 'or',
    5: 'and',
    6: 'lsh',
    7: 'rsh',
    8: 'neg',
    9: 'mod',
    10: 'xor',
    11: 'mov',
    12: 'arsh',
    13: '(endian)',
}

JMP_OPCODES = {
    0: 'ja',
    1: 'jeq',
    2: 'jgt',
    3: 'jge',
    4: 'jset',
    5: 'jne',
    6: 'jsgt',
    7: 'jsge',
    8: 'call',
    9: 'exit',
    10: 'jlt',
    11: 'jle',
    12: 'jslt',
    13: 'jsle',
}

MODES = {
    0: 'imm',
    1: 'abs',
    2: 'ind',
    3: 'mem',
    6: 'xadd',
}

SIZES = {
    0: 'w',
    1: 'h',
    2: 'b',
    3: 'dw',
}

# All opcodes have the similar format of:
# 0-2: class identifier
# 3-7: class specific opcode

# For LD and store instructions:
# 3-4: size
# 5-7: mode
BPF_CLASS_LD = 0
BPF_CLASS_LDX = 1
BPF_CLASS_ST = 2
BPF_CLASS_STX = 3

# For ALU and jump instructions:
# 3: Source (register or immediate)
# 4-7: ALU opcode
BPF_CLASS_ALU32 = 4
BPF_CLASS_JMP = 5
BPF_CLASS_JMP32 = 6
BPF_CLASS_ALU = 7

BPF_ALU_NEG = 8
BPF_ALU_END = 13

# Pack an instruction into a byte array
# The instruction is packed as follows:
# Byte: 0: opcode
# Byte: 1: source register and destination register
# Short: 2: offset
# Int: 4: immediate value
def gen_inst(source_register : int, dest_register : int, opcode : int, offset : int, immediate : int) -> bytes:
    return Inst.pack(opcode, source_register << 4 | dest_register, offset, immediate)

# Generate a load or store opcode
def gen_ld_st_opcode(op_class : int, size : int, mode : int) -> int:
    return op_class << 3 | size << 1 | mode

# Generate an ALU or JMPM opcode
def gen_alu_or_jump_opcode(op_class : int, source : int, opcode : int) -> int:
    return op_class << 3 | source << 2 | opcode

def encode_and_print_instruction(inst : bytes):
    # Check for special case of BPF_LDDDW instruction which is two instructions
    if inst[0] & 7 == 0:
        inst = inst + b"\x00\x00\x00\x00\x00\x00\x00\x00"
    mnemonic = disassembler.disassemble_one(inst, 0)
    if "Warnings" in mnemonic[0]:
        return
    # If the mnemonic tuple contains more than one element, skip it
    print(mnemonic[0], "=", end="")
    print("\"", end="")
    for byte in inst:
        print("\\x{:02x}".format(byte), end="")
    print("\"")

# Generate all possible instructions

# Load and store instructions
for op_class in range(4):
    for size in range(4):
        for mode in range(8):
            opcode = gen_ld_st_opcode(op_class, size, mode)
            for source_register in range(11):
                for dest_register in range(11):
                    inst = gen_inst(source_register, dest_register, opcode, 0, 0)
                    encode_and_print_instruction(inst)

# ALU and JMP instructions (range 4-7)
for op_class in range(4, 8):
    for source in range(2):
        for alu_op in range(14):
            opcode = gen_alu_or_jump_opcode(op_class, source, alu_op)
            for source_register in range(11):
                for dest_register in range(11):
                    inst = gen_inst(source_register, dest_register, opcode, 0, 0)
                    encode_and_print_instruction(inst)

