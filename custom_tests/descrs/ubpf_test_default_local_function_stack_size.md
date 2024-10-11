## Test Description

This custom test guarantees that the eBPF program's manipulation of its stack has the intended effect. The eBPF program is JIT'd/interpreted under the assumption that each of the functions will use the default amount of stack space (256 bytes). This test will guarantee that with an eBPF program that writes at specific spots in the program's stack and then checks whether those writes put data in the proper spot on the program's stack.

### eBPF Program Source

```
stb [%r10-1], 0x1
stb [%r10-2], 0x2
stb [%r10-3], 0x3
stb [%r10-4], 0x4
call local func1
mov %r0, 0x0
exit

func1:
stb [%r10-1], 0x11
stb [%r10-2], 0x12
stb [%r10-3], 0x13
stb [%r10-4], 0x14
exit
```

### Expected Behavior

Given the size of the stack usage for each function (see above), the contents of the memory at the end of the program will be:

```
0x1efc: 0x14
0x1efd: 0x13
0x1efe: 0x12
0x1eff: 0x11
...
0x1ffa: 0x00
0x1ffb: 0x00
0x1ffc: 0x04
0x1ffd: 0x03
0x1ffe: 0x02
0x1fff: 0x01
```
