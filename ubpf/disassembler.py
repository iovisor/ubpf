import struct
try:
    from StringIO import StringIO as io
except ImportError:
    from io import StringIO as io

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

BPF_CLASS_LD = 0
BPF_CLASS_LDX = 1
BPF_CLASS_ST = 2
BPF_CLASS_STX = 3
BPF_CLASS_ALU32 = 4
BPF_CLASS_JMP = 5
BPF_CLASS_JMP32 = 6
BPF_CLASS_ALU = 7

BPF_ALU_NEG = 8
BPF_ALU_END = 13

def R(reg):
    return "%r" + str(reg)

def I(imm):
    return "%#x" % imm

def M(base, off):
    if off != 0:
        return "[%s%s]" % (base, O(off))
    else:
        return "[%s]" % base

def O(off):
    if off <= 32767:
        return "+" + str(off)
    else:
        return "-" + str(65536-off)

def disassemble_one(data, offset, verbose = False):
    code, regs, off, imm = Inst.unpack_from(data, offset)
    dst_reg = regs & 0xf
    src_reg = (regs >> 4) & 0xf
    clz = code & 7

    increment = 8

    class Field(object):
        def __init__(self, name, value):
            self.name = name
            self.used = False
            self.value = value

        def set_used(self):
            self.used = True

        def set_unused(self):
            self.used = False

    fields = {}
    fields['off'] = Field("offset", off)
    fields['dst_reg'] = Field("destination register", dst_reg)
    fields['src_reg'] = Field("source register", src_reg)
    fields['imm'] = Field("immediate", imm)

    disassembled = ""

    class_name = CLASSES.get(clz)

    if clz == BPF_CLASS_ALU or clz == BPF_CLASS_ALU32:
        source = (code >> 3) & 1
        opcode = (code >> 4) & 0xf
        opcode_name = ALU_OPCODES.get(opcode)
        if clz == BPF_CLASS_ALU32:
            opcode_name += "32"

        if opcode == BPF_ALU_END:
            opcode_name = source == 1 and "be" or "le"
            fields["imm"].used = True
            fields["dst_reg"].used = True
            disassembled = f'{opcode_name}{imm} {R(dst_reg)}'
        elif opcode == BPF_ALU_NEG:
            fields["dst_reg"].used = True
            disassembled = f'{opcode_name} {R(dst_reg)}'
        elif source == 0:
            fields["dst_reg"].used = True
            fields["imm"].used = True
            disassembled = f'{opcode_name} {R(dst_reg)}, {I(imm)}'
        else:
            fields["dst_reg"].used = True
            fields["src_reg"].used = True
            disassembled = f'{opcode_name} {R(dst_reg)}, {R(src_reg)}'
    elif clz == BPF_CLASS_JMP or clz == BPF_CLASS_JMP32:
        source = (code >> 3) & 1
        opcode = (code >> 4) & 0xf
        opcode_name = JMP_OPCODES.get(opcode)
        if clz == BPF_CLASS_JMP32:
            opcode_name += "32"

        if opcode_name == "exit":
            disassembled = f'{opcode_name}'
        elif opcode_name == "call":
            if src_reg == 1:
                opcode_name += " local"
            fields["imm"].used = True
            disassembled = f'{opcode_name} {I(imm)}'
        elif opcode_name == "ja":
            fields["off"].used = True
            disassembled = f'{opcode_name} {O(off)}'
        elif source == 0:
            fields["dst_reg"].used = True
            fields["imm"].used = True
            fields["off"].used = True
            disassembled = f'{opcode_name} {R(dst_reg)}, {I(imm)}, {O(off)}'
        else:
            fields["dst_reg"].used = True
            fields["src_reg"].used = True
            fields["off"].used = True
            disassembled = f'{opcode_name} {R(dst_reg)}, {R(src_reg)}, {O(off)}'
    elif clz == BPF_CLASS_LD:
        size = (code >> 3) & 3
        mode = (code >> 5) & 7
        mode_name = MODES.get(mode, str(mode))
        size_name = SIZES.get(size, str(size))
        if clz == BPF_CLASS_LD and size == 0x3 and src_reg == 0:
            # Make sure that we skip the next instruction because we use it here!
            increment += 8
            _, _, _, imm2 = Inst.unpack_from(data, offset+8)
            imm = (imm2 << 32) | imm
            fields["dst_reg"].used = True
            fields["imm"].used = True
            disassembled = f'{class_name}{size_name} {R(dst_reg)}, {I(imm)}'
        else:
            result = f"unknown/unsupported special LOAD instruction {code=:x}"

    elif clz == BPF_CLASS_LD or clz == BPF_CLASS_LDX or clz == BPF_CLASS_ST or clz == BPF_CLASS_STX:
        size = (code >> 3) & 3
        mode = (code >> 5) & 7
        mode_name = MODES.get(mode, str(mode))
        size_name = SIZES.get(size, str(size))
        if clz == BPF_CLASS_LDX:
            fields["dst_reg"].used = True
            fields["src_reg"].used = True
            fields["off"].used = True
            disassembled = f'{class_name}{size_name} {R(dst_reg)}, {M(R(src_reg), off)}'
        elif clz == BPF_CLASS_ST:
            fields["dst_reg"].used = True
            fields["off"].used = True
            fields["imm"].used = True
            disassembled = f'{class_name}{size_name} {M(R(dst_reg), off)}, {I(imm)}'
        elif clz == BPF_CLASS_STX:
            fields["dst_reg"].used = True
            fields["src_reg"].used = True
            fields["off"].used = True
            disassembled = f'{class_name}{size_name} {M(R(dst_reg), off)}, {R(src_reg)}'
        else:
            disassembled = f'unknown/unsupported mem instruction {code=:x}'
    else:
        disassembled = f'unknown/unsupported instruction {code=:x}'

    warnings = ""
    for k in fields.keys():
        if not fields[k].used and fields[k].value != 0:
            if len(warnings) != 0:
                warnings += "; "
            warnings += f"The {fields[k].name} field of the instruction has a value but it is not used by the instruction"

    if len(warnings) != 0:
        disassembled += f"\n\tWarnings: {warnings}."
        disassembled += "\n"

    if verbose:
        disassembled += "\nDetails:\n"
        disassembled += f"\tClass: 0x{clz:x}"
        disassembled += "\n"
        disassembled += f"\tRegs: 0x{regs:x}"
        disassembled += "\n"
        disassembled += f"\tOffset: 0x{off:x}"
        disassembled += "\n"
        disassembled += f"\tImmediate: 0x{imm:x}"
        disassembled += "\n"
        disassembled += "-----------------"

    return disassembled, increment

def disassemble(data, verbose = False):
    output = io()
    offset = 0
    while offset < len(data):
        (s, increment) = disassemble_one(data, offset, verbose)
        if s:
            output.write(s + "\n")
        offset += increment
    return output.getvalue()
