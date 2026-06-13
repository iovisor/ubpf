import os
import tempfile
import struct
import re
import sys
import traceback
from subprocess import Popen, PIPE
try:
    from nose.plugins.skip import Skip, SkipTest
except Exception:
    class SkipTest(Exception):
        pass

    Skip = SkipTest
import ubpf.assembler
import testdata
PROFILE = os.environ.get("UBPF_VM_PROFILE", "legacy").strip().lower()

if PROFILE not in ("legacy", "safe"):
    raise RuntimeError("UBPF_VM_PROFILE must be 'legacy' or 'safe'")

def _find_vm_binary():
    env_vm = os.environ.get("UBPF_VM_BINARY")
    if env_vm:
        return env_vm

    repo_root = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..")
    candidates = [
        os.path.join(repo_root, "build", "bin", "Debug", "ubpf_test.exe"),
        os.path.join(repo_root, "build", "bin", "Release", "ubpf_test.exe"),
        os.path.join(repo_root, "build", "bin", "ubpf_test"),
        os.path.join(repo_root, "vm", "test"),
    ]

    for candidate in candidates:
        if os.path.exists(candidate):
            return candidate

    return candidates[0]

VM = _find_vm_binary()

def check_datafile(filename):
    """
    Given assembly source code and an expected result, run the eBPF program and
    verify that the result matches.
    """
    data = testdata.read(filename)
    if 'asm' not in data and 'raw' not in data:
        raise SkipTest("no asm or raw section in datafile")
    if 'result' not in data and 'error' not in data and 'error pattern' not in data:
        raise SkipTest("no result or error section in datafile")
    if not os.path.exists(VM):
        raise SkipTest("VM not found")

    if 'raw' in data:
        code = b''.join(struct.pack("=Q", x) for x in data['raw'])
    else:
        code = ubpf.assembler.assemble(data['asm'])

    memfile = None

    cmd = [VM, '--profile', PROFILE]
    if 'mem' in data:
        memfile = tempfile.NamedTemporaryFile()
        memfile.write(data['mem'])
        memfile.flush()
        cmd.extend(['-m', memfile.name])
    if 'reload' in data:
        cmd.extend(['-R'])
    if 'unload' in data:
        cmd.extend(['-U'])

    cmd.append('-')

    vm = Popen(cmd, stdin=PIPE, stdout=PIPE, stderr=PIPE)

    stdout, stderr = vm.communicate(code)
    stdout = stdout.decode("utf-8")
    stderr = stderr.decode("utf-8")
    stderr = stderr.strip()

    if memfile:
        memfile.close()

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

def run_all_datafiles():
    total = 0
    passed = 0
    skipped = []
    failures = []

    for filename in testdata.list_files():
        total += 1
        try:
            check_datafile(filename)
            passed += 1
        except SkipTest as ex:
            skipped.append((filename, str(ex)))
        except Exception as ex:
            failures.append((filename, ex, traceback.format_exc()))

    for filename, reason in skipped:
        print("SKIP %s: %s" % (filename, reason), file=sys.stderr)

    for filename, _, details in failures:
        print("FAIL %s" % filename, file=sys.stderr)
        print(details, file=sys.stderr)

    print(
        "Profile %s: %d passed, %d skipped, %d failed out of %d"
        % (PROFILE, passed, len(skipped), len(failures), total)
    )

    return 0 if not failures else 1

if __name__ == "__main__":
    sys.exit(run_all_datafiles())
