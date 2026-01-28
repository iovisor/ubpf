from .asm_parser import parse, Reg, Imm, MemRef, Label, LabelRef
import struct
try:
    from StringIO import StringIO as io
except ImportError:
    from io import BytesIO as io

Inst = struct.Struct("BBHI")

MEM_SIZES = {
    'w': 0,
    'h': 1,
    'b': 2,
    'dw': 3,
}

MEM_LOAD_OPS = { 'ldx' + k: (0x61 | (v << 3)) for k, v in list(MEM_SIZES.items()) }
MEM_LOAD_SX_OPS = { 'ldxs' + k: (0x81 | (v << 3)) for k, v in list(MEM_SIZES.items()) if k != 'dw' }
MEM_STORE_IMM_OPS = { 'st' + k: (0x62 | (v << 3))  for k, v in list(MEM_SIZES.items()) }
MEM_STORE_REG_OPS = { 'stx' + k: (0x63 | (v << 3)) for k, v in list(MEM_SIZES.items()) }

UNARY_ALU_OPS = {
    'neg': 8,
}

BINARY_ALU_OPS = {
    'add': 0,
    'sub': 1,
    'mul': 2,
    'div': 3,
    'or': 4,
    'and': 5,
    'lsh': 6,
    'rsh': 7,
    'mod': 9,
    'xor': 10,
    'mov': 11,
    'arsh': 12,
}

# Signed division and modulo operations (same opcode as div/mod but with offset=1)
SIGNED_BINARY_ALU_OPS = {
    'sdiv': 3,
    'smod': 9,
}

UNARY_ALU32_OPS = { k + '32': v for k, v in list(UNARY_ALU_OPS.items()) }
BINARY_ALU32_OPS = { k + '32': v for k, v in list(BINARY_ALU_OPS.items()) }
SIGNED_BINARY_ALU32_OPS = { k + '32': v for k, v in list(SIGNED_BINARY_ALU_OPS.items()) }

END_OPS = {
    'le16': (0xd4, 16),
    'le32': (0xd4, 32),
    'le64': (0xd4, 64),
    'be16': (0xdc, 16),
    'be32': (0xdc, 32),
    'be64': (0xdc, 64),
    'bswap16': (0xd7, 16),
    'bswap32': (0xd7, 32),
    'bswap64': (0xd7, 64),
}

JMP_CMP_OPS = {
    'jeq': 1,
    'jgt': 2,
    'jge': 3,
    'jset': 4,
    'jne': 5,
    'jsgt': 6,
    'jsge': 7,
    'jlt': 10,
    'jle': 11,
    'jslt': 12,
    'jsle': 13,
}

JMP_MISC_OPS = {
    'ja': 0,
    'call': 8,
    'exit': 9,
}

def pack(opcode, dst, src, offset, imm):
    return Inst.pack(opcode & 0xff, (dst | (src << 4)) & 0xff, offset & 0xffff, imm & 0xffffffff)

def assemble_binop(op, cls, ops, dst, src, offset):
    opcode = cls | (ops[op] << 4)
    if isinstance(src, Imm):
        return pack(opcode, dst.num, 0, offset, src.value)
    else:
        return pack(opcode | 0x08, dst.num, src.num, offset, 0)

def assemble_one(inst):
    op = inst[0]
    if op in MEM_LOAD_OPS:
        opcode = MEM_LOAD_OPS[op]
        return pack(opcode, inst[1].num, inst[2].reg.num, inst[2].offset, 0)
    elif op in MEM_LOAD_SX_OPS:
        opcode = MEM_LOAD_SX_OPS[op]
        return pack(opcode, inst[1].num, inst[2].reg.num, inst[2].offset, 0)
    elif op == "lddw":
        a = pack(0x18, inst[1].num, 0, 0, inst[2].value)
        b = pack(0, 0, 0, 0, inst[2].value >> 32)
        return a + b
    elif op in MEM_STORE_IMM_OPS:
        opcode = MEM_STORE_IMM_OPS[op]
        return pack(opcode, inst[1].reg.num, 0, inst[1].offset, inst[2].value)
    elif op in MEM_STORE_REG_OPS:
        opcode = MEM_STORE_REG_OPS[op]
        return pack(opcode, inst[1].reg.num, inst[2].num, inst[1].offset, 0)
    elif op in UNARY_ALU_OPS:
        opcode = 0x07 | (UNARY_ALU_OPS[op] << 4)
        return pack(opcode, inst[1].num, 0, 0, 0)
    elif op in UNARY_ALU32_OPS:
        opcode = 0x04 | (UNARY_ALU32_OPS[op] << 4)
        return pack(opcode, inst[1].num, 0, 0, 0)
    elif op in BINARY_ALU_OPS:
        return assemble_binop(op, 0x07, BINARY_ALU_OPS, inst[1], inst[2], 0)
    elif op in BINARY_ALU32_OPS:
        return assemble_binop(op, 0x04, BINARY_ALU32_OPS, inst[1], inst[2], 0)
    elif op in SIGNED_BINARY_ALU_OPS:
        return assemble_binop(op, 0x07, SIGNED_BINARY_ALU_OPS, inst[1], inst[2], 1)
    elif op in SIGNED_BINARY_ALU32_OPS:
        return assemble_binop(op, 0x04, SIGNED_BINARY_ALU32_OPS, inst[1], inst[2], 1)
    elif op in END_OPS:
        opcode, imm = END_OPS[op]
        return pack(opcode, inst[1].num, 0, 0, imm)
    elif op in JMP_CMP_OPS:
        return assemble_binop(op, 0x05, JMP_CMP_OPS, inst[1], inst[2], inst[3])
    elif op in JMP_MISC_OPS:
        opcode = 0x05 | (JMP_MISC_OPS[op] << 4)
        if op == 'ja':
            return pack(opcode, 0, 0, inst[1], 0)
        elif op == 'call':
            return pack(opcode, 0, 0, 0, inst[1].value)
        elif op == 'exit':
            return pack(opcode, 0, 0, 0, 0)
    else:
        raise ValueError("unexpected instruction %r" % op)

def resolve_label_ref(label_ref, current_idx, labels):
    """
    Resolve a label reference to an offset.
    
    Args:
        label_ref: LabelRef or int (offset)
        current_idx: Current instruction index
        labels: Dictionary mapping label names to instruction indices
    
    Returns:
        Resolved offset as an integer
    """
    if isinstance(label_ref, LabelRef):
        if label_ref.name not in labels:
            raise ValueError("Undefined label: %s" % label_ref.name)
        target_idx = labels[label_ref.name]
        offset = target_idx - current_idx - 1
        return offset
    else:
        # Already an offset
        return label_ref

def resolve_labels_in_inst(inst, current_idx, labels):
    """
    Replace label references in an instruction with calculated offsets.
    
    Args:
        inst: Instruction tuple
        current_idx: Current instruction index
        labels: Dictionary mapping label names to instruction indices
    
    Returns:
        Instruction tuple with labels resolved to offsets
    """
    if not inst:
        return inst
    
    op = inst[0]
    
    # Handle jump comparison operations (jeq, jgt, etc.)
    if op in JMP_CMP_OPS:
        # inst = (op, reg, reg/imm, offset/labelref)
        target = inst[3]
        resolved_offset = resolve_label_ref(target, current_idx, labels)
        return (inst[0], inst[1], inst[2], resolved_offset)
    
    # Handle unconditional jump (ja)
    elif op == 'ja':
        # inst = ('ja', offset/labelref)
        target = inst[1]
        resolved_offset = resolve_label_ref(target, current_idx, labels)
        return ('ja', resolved_offset)
    
    # Handle call instruction with 'local' keyword
    elif op == 'call' and len(inst) > 2 and inst[1] == 'local':
        # inst = ('call', 'local', imm/labelref)
        target = inst[2]
        if isinstance(target, LabelRef):
            if target.name not in labels:
                raise ValueError("Undefined label: %s" % target.name)
            target_idx = labels[target.name]
            # For 'call local', we use the absolute instruction index
            resolved_imm = Imm(target_idx)
            return ('call', resolved_imm)
        else:
            # Already an Imm
            return ('call', target)
    
    # No labels to resolve in this instruction
    return inst

def assemble(source):
    """
    Assemble BPF assembly source code to bytecode.
    
    This uses a two-pass approach:
    1. First pass: collect labels and build instruction list
    2. Second pass: resolve label references and assemble
    
    Args:
        source: Assembly source code as a string
    
    Returns:
        Assembled bytecode as bytes
    """
    parsed = parse(source)
    
    # Pass 1: Collect labels and instructions
    labels = {}
    instructions = []
    instruction_idx = 0
    
    for item in parsed:
        if not item:
            # Empty line
            continue
        
        # item can be:
        # 1. A tuple with (Label, 'opcode', ...) when label and instruction on same line
        # 2. Just Label when only label on the line
        # 3. A tuple ('opcode', ...) when just an instruction
        label = None
        inst = None
        
        if isinstance(item, tuple) and len(item) > 0:
            # Check if first element is a Label
            if isinstance(item[0], Label):
                label = item[0]
                # The rest is the instruction
                if len(item) > 1:
                    inst = item[1:]
            else:
                # It's just an instruction tuple
                inst = item
        elif isinstance(item, Label):
            # Standalone label
            label = item
        else:
            # Shouldn't happen, but just in case
            inst = item
        
        # Process label if found
        if label:
            if label.name in labels:
                raise ValueError("Duplicate label: %s" % label.name)
            labels[label.name] = instruction_idx
        
        # Process instruction if found
        if inst:
            instructions.append(inst)
            # LDDW takes 2 instruction slots
            if inst[0] == 'lddw':
                instruction_idx += 2
            else:
                instruction_idx += 1
    
    # Pass 2: Resolve labels and assemble
    output = io()
    instruction_idx = 0
    for inst in instructions:
        resolved_inst = resolve_labels_in_inst(inst, instruction_idx, labels)
        output.write(assemble_one(resolved_inst))
        # LDDW takes 2 instruction slots
        if inst[0] == 'lddw':
            instruction_idx += 2
        else:
            instruction_idx += 1
    
    return output.getvalue()
