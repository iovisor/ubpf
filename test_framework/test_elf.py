import sys
import os
import tempfile
import struct
import re
import elftools.elf.structs
from subprocess import Popen, PIPE
from nose.plugins.skip import Skip, SkipTest
from elftools.construct import Container
from elftools.elf.constants import SH_FLAGS
import testdata
import ubpf.assembler
VM = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "vm", "test")

def template():
    parts = {}
    parts['order'] = []
    def add(name, value):
        parts[name] = value
        parts['order'].append(name)

    add('ehdr', Container(
        e_ident=Container(
            EI_MAG=[0x7f, ord('E'), ord('L'), ord('F')],
            EI_CLASS='ELFCLASS64',
            EI_DATA='ELFDATA2LSB',
            EI_VERSION='EV_CURRENT',
            EI_OSABI='ELFOSABI_SYSV',
            EI_ABIVERSION=0),
        e_type='ET_REL',
        e_machine='EM_NONE',
        e_version=0,
        e_entry=0,
        e_phoff=0,
        e_shoff=64,
        e_flags=0,
        e_ehsize=64,
        e_phentsize=0,
        e_phnum=0,
        e_shentsize=64,
        e_shnum=5,
        e_shstrndx=2))

    add('first_shdr', Container(
        sh_name=0,
        sh_type='SHT_NULL',
        sh_flags=0,
        sh_addr=0,
        sh_offset=0,
        sh_size=0,
        sh_link=0,
        sh_info=0,
        sh_addralign=0,
        sh_entsize=0))

    add('text_shdr', Container(
        sh_name=1,
        sh_type='SHT_PROGBITS',
        sh_flags=SH_FLAGS.SHF_ALLOC|SH_FLAGS.SHF_EXECINSTR,
        sh_addr=0,
        sh_offset=384,
        sh_size=24,
        sh_link=0,
        sh_info=0,
        sh_addralign=8,
        sh_entsize=0))

    add('strtab_shdr', Container(
        sh_name=7,
        sh_type='SHT_STRTAB',
        sh_flags=0,
        sh_addr=0,
        sh_offset=408,
        sh_size=34,
        sh_link=0,
        sh_info=0,
        sh_addralign=1,
        sh_entsize=0))

    add('symtab_shdr', Container(
        sh_name=15,
        sh_type='SHT_SYMTAB',
        sh_flags=0,
        sh_addr=0,
        sh_offset=442,
        sh_size=48,
        sh_link=2,
        sh_info=0,
        sh_addralign=8,
        sh_entsize=24))

    add('rel_shdr', Container(
        sh_name=23,
        sh_type='SHT_REL',
        sh_flags=0,
        sh_addr=0,
        sh_offset=490,
        sh_size=16,
        sh_link=3,
        sh_info=1,
        sh_addralign=8,
        sh_entsize=16))

    # return sqrti(42*42)
    asm = """
mov %r1, 1764
call 0xffffffff
exit
"""

    text = ubpf.assembler.assemble(asm)

    add("text", text)
    add("strtab", b"\0.text\0.strtab\0.symtab\0.rel\0sqrti\0")
    add("first_sym", Container(
        st_name=0,
        st_value=0,
        st_size=0,
        st_info=Container(bind='STB_WEAK', type='STT_FUNC'),
        st_other=Container(local=0, visibility='STV_DEFAULT'),
        st_shndx=0))
    add("sqrti_sym", Container(
        st_name=28,
        st_value=0,
        st_size=0,
        st_info=Container(bind='STB_WEAK', type='STT_FUNC'),
        st_other=Container(local=0, visibility='STV_DEFAULT'),
        st_shndx=0))
    add("sqrti_rel", Container(
        r_info=(1 << 32) | 2,
        r_info_sym=0,
        r_info_type=0,
        r_offset=8))

    return parts

def serialize(parts):
    s = elftools.elf.structs.ELFStructs(elfclass=64)
    s.create_basic_structs()
    ehdr = parts['ehdr']
    s.create_advanced_structs(ehdr['e_type'], ehdr['e_machine'], ehdr['e_ident']['EI_OSABI'])
    tmp = []
    offset = 0

    for name in parts['order']:
        part = parts[name]
        serializer = lambda x: x
        if name == 'ehdr':
            serializer = s.Elf_Ehdr.build
        elif name.endswith('shdr'):
            serializer = s.Elf_Shdr.build
        elif name.endswith('rel'):
            serializer = s.Elf_Rel.build
        elif name.endswith('sym'):
            serializer = s.Elf_Sym.build

        data = serializer(part)
        tmp.append(data)
        #sys.stderr.write("Wrote %s size %d at offset %d\n" % (name, len(data), offset))
        offset += len(data)

    return b''.join(tmp)

def generate_elf(pyelf):
    parts = template()
    exec(pyelf, parts)
    return serialize(parts)

def check_datafile(filename):
    """
    """
    data = testdata.read(filename)
    if 'pyelf' not in data:
        raise SkipTest("no pyelf section in datafile")
    if 'result' not in data and 'error' not in data and 'error pattern' not in data:
        raise SkipTest("no result or error section in datafile")
    if not os.path.exists(VM):
        raise SkipTest("VM not found")

    elf = generate_elf(data['pyelf'])

    cmd = [VM]

    cmd.append('-')

    vm = Popen(cmd, stdin=PIPE, stdout=PIPE, stderr=PIPE)

    stdout, stderr = vm.communicate(elf)
    stdout = stdout.decode("utf-8")
    stderr = stderr.decode("utf-8")
    stderr = stderr.strip()

    if 'error' in data:
        if data['error'] != stderr:
            raise AssertionError("Expected error %r, got %r" % (data['error'], stderr))
    elif 'error pattern' in data:
        if not re.search(data['error pattern'], stderr):
            raise AssertionError("Expected error matching %r, got %r" % (data['error pattern'], stderr))
    else:
        if stderr:
            raise AssertionError("Unexpected error %r" % stderr)

    if 'result' in data:
        if vm.returncode != 0:
            raise AssertionError("VM exited with status %d, stderr=%r" % (vm.returncode, stderr))
        expected = int(data['result'], 0)
        result = int(stdout, 0)
        if expected != result:
            raise AssertionError("Expected result 0x%x, got 0x%x, stderr=%r" % (expected, result, stderr))
    else:
        if vm.returncode == 0:
            raise AssertionError("Expected VM to exit with an error code")

def test_datafiles():
    # Nose test generator
    # Creates a testcase for each datafile
    for filename in testdata.list_files():
        yield check_datafile, filename
