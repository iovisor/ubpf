## Test Description

This custom test program tests whether JIT'd eBPF programs properly pass the original context
to external helper dispatcher even when (eBPF) register r0 has been modified. The original
context to the eBPF program is passed in (eBPF) register r0. Subsequent changes to that
register by the eBPF program should *not* affect that context (which is given to the
helper function external dispatcher).