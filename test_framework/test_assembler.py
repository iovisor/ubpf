import struct
from nose.plugins.skip import Skip, SkipTest
import ubpf.assembler
import ubpf.disassembler
import testdata
try:
    xrange
except NameError:
    xrange = range

# Just for assertion messages
def try_disassemble(inst):
    data = struct.pack("=Q", inst)
    try:
        return ubpf.disassembler.disassemble(data).strip()
    except ValueError:
        return "<error>"

def check_datafile(filename):
    """
    Verify that the result of assembling the 'asm' section matches the
    'raw' section.
    """
    data = testdata.read(filename)
    if 'asm' not in data:
        raise SkipTest("no asm section in datafile")
    if 'raw' not in data:
        raise SkipTest("no raw section in datafile")

    bin_result = ubpf.assembler.assemble(data['asm'])
    assert len(bin_result) % 8 == 0
    assert len(bin_result) / 8 == len(data['raw'])

    for i in xrange(0, len(bin_result), 8):
        j = int(i/8)
        inst, = struct.unpack_from("=Q", bin_result[i:i+8])
        exp = data['raw'][j]
        if exp != inst:
            raise AssertionError("Expected instruction %d to be %#x (%s), but was %#x (%s)" %
                (j, exp, try_disassemble(exp), inst, try_disassemble(inst)))

def test_datafiles():
    # Nose test generator
    # Creates a testcase for each datafile
    for filename in testdata.list_files():
        yield check_datafile, filename

# Label support tests
def test_label_forward_jump():
    """Test forward jump with label"""
    source = """
    mov %r0, 1
    ja done
    mov %r0, 2
    done:
    exit
    """
    bytecode = ubpf.assembler.assemble(source)
    # Should have 4 instructions (mov, ja, mov, exit)
    assert len(bytecode) == 4 * 8
    
    # Verify the ja instruction has correct offset (+1 to skip mov and reach done/exit)
    _, _, off, _ = struct.unpack_from("=BBHI", bytecode, 8)
    assert off == 1, "Expected ja offset=1, got %s" % off

def test_label_backward_jump():
    """Test backward jump (loop) with label"""
    source = """
    mov %r0, 10
    loop:
    sub %r0, 1
    jne %r0, 0, loop
    exit
    """
    bytecode = ubpf.assembler.assemble(source)
    assert len(bytecode) == 4 * 8
    
    # Verify the jne instruction has correct offset (-2 to jump back to loop)
    _, _, off, _ = struct.unpack_from("=BBHI", bytecode, 16)
    # Convert to signed
    signed_off = off if off < 32768 else off - 65536
    assert signed_off == -2, "Expected jne offset=-2, got %s" % signed_off

def test_label_conditional_jump():
    """Test conditional jump with label"""
    source = """
    jeq %r1, %r2, equal
    mov %r0, 1
    ja done
    equal:
    mov %r0, 0
    done:
    exit
    """
    bytecode = ubpf.assembler.assemble(source)
    assert len(bytecode) == 5 * 8
    
    # Verify jeq offset (+2 to skip mov and ja)
    _, _, off, _ = struct.unpack_from("=BBHI", bytecode, 0)
    assert off == 2, "Expected jeq offset=2, got %s" % off
    
    # Verify ja offset (+1 to skip mov)
    _, _, off, _ = struct.unpack_from("=BBHI", bytecode, 16)
    assert off == 1, "Expected ja offset=1, got %s" % off

def test_label_local_call():
    """Test local function call with label"""
    source = """
    mov %r1, 5
    call local double
    exit
    double:
    add %r1, %r1
    mov %r0, %r1
    exit
    """
    bytecode = ubpf.assembler.assemble(source)
    assert len(bytecode) == 6 * 8
    
    # Verify call local has src_reg=1 and correct relative offset
    _, regs, _, imm = struct.unpack_from("=BBHI", bytecode, 8)
    src_reg = (regs >> 4) & 0xf
    assert src_reg == 1, "Expected src_reg=1 for call local, got %s" % src_reg
    assert imm == 1, "Expected call local offset=1, got %s" % imm

def test_label_on_same_line():
    """Test label and instruction on same line"""
    source = """
    loop: sub %r0, 1
    jne %r0, 0, loop
    exit
    """
    bytecode = ubpf.assembler.assemble(source)
    assert len(bytecode) == 3 * 8
    
    # Verify jne has correct offset (-2)
    _, _, off, _ = struct.unpack_from("=BBHI", bytecode, 8)
    signed_off = off if off < 32768 else off - 65536
    assert signed_off == -2, "Expected jne offset=-2, got %s" % signed_off

def test_label_undefined_error():
    """Test error for undefined label"""
    source = "ja undefined\nexit"
    try:
        ubpf.assembler.assemble(source)
        assert False, "Should have raised ValueError for undefined label"
    except ValueError as e:
        assert "Undefined label" in str(e)

def test_label_duplicate_error():
    """Test error for duplicate label"""
    source = """
    foo:
    mov %r0, 1
    foo:
    exit
    """
    try:
        ubpf.assembler.assemble(source)
        assert False, "Should have raised ValueError for duplicate label"
    except ValueError as e:
        assert "Duplicate label" in str(e)

def test_label_with_lddw():
    """Test label offset calculation with LDDW instruction"""
    source = """
    lddw %r0, 0x123456789
    ja done
    mov %r1, 1
    done:
    exit
    """
    bytecode = ubpf.assembler.assemble(source)
    # lddw takes 2 slots, ja, mov, exit = 5 instructions total
    assert len(bytecode) == 5 * 8
    
    # Verify ja offset accounts for lddw taking 2 slots (+1 to skip mov)
    _, _, off, _ = struct.unpack_from("=BBHI", bytecode, 16)
    assert off == 1, "Expected ja offset=1, got %s" % off

def test_numeric_offset_backward_compatibility():
    """Test that numeric offsets still work"""
    source = """
    mov %r0, 1
    ja +2
    mov %r0, 2
    exit
    """
    bytecode = ubpf.assembler.assemble(source)
    assert len(bytecode) == 4 * 8
    
    # Verify ja has offset +2
    _, _, off, _ = struct.unpack_from("=BBHI", bytecode, 8)
    assert off == 2, "Expected ja offset=2, got %s" % off
