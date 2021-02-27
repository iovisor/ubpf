import os
import tempfile
import struct
from subprocess import Popen, PIPE
from nose.plugins.skip import Skip, SkipTest
import ubpf.assembler
import testdata
VM = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "vm", "test")

def check_datafile(filename):
    """
    Given assembly source code and an expected result, run the eBPF program and
    verify that the result matches.
    """
    data = testdata.read(filename)
    if 'asm' not in data and 'raw' not in data:
        raise SkipTest("no asm or raw section in datafile")
    if 'result' not in data and 'verifier error' not in data:
        raise SkipTest("no result or verifier error section in datafile")
    if 'error' in data or 'error pattern' in data:
        raise SkipTest("non-verifier error section in datafile")
    if not os.path.exists(VM):
        raise SkipTest("VM not found")

    if 'raw' in data:
        code = b''.join(struct.pack("=Q", x) for x in data['raw'])
    else:
        code = ubpf.assembler.assemble(data['asm'])

    memfile = None

    cmd = [VM]
    if 'mem' in data:
        memfile = tempfile.NamedTemporaryFile()
        memfile.write(data['mem'])
        memfile.flush()
        cmd.extend(['-m', memfile.name])

    cmd.extend(['-v', '-'])

    vm = Popen(cmd, stdin=PIPE, stdout=PIPE, stderr=PIPE)

    stdout, stderr = vm.communicate(code)
    stdout = stdout.decode("utf-8")
    stderr = stderr.decode("utf-8")
    stderr = stderr.strip()

    if memfile:
        memfile.close()

    if 'verifier error' in data:
        expected = data["verifier error"] + "\nFailed verification"
        if expected != stderr:
            raise AssertionError("Expected error %r, got %r" % (expected, stderr))
        if vm.returncode == 0:
            raise AssertionError("Expected VM to exit with an error code")
    elif 'error' in data or 'error-pattern' in data:
        if vm.returncode == 0:
            raise AssertionError("Expected VM to exit with an error code")
    else:
        if vm.returncode != 0:
            raise AssertionError("VM exited with status %d, stderr=%r" % (vm.returncode, stderr))

def test_datafiles():
    # Nose test generator
    # Creates a testcase for each datafile
    for filename in testdata.list_files():
        yield check_datafile, filename
