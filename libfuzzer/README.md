# ubpf_fuzzer

This is a libfuzzer based fuzzer.

To build, run:
```
cmake \
    -G Ninja \
    -S . \
    -B build \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_COMPILER=clang \
    -DCMAKE_CXX_COMPILER=clang++ \
    -DUBPF_ENABLE_LIBFUZZER=1 \
    -DCMAKE_BUILD_TYPE=Debug

cmake --build build
```

To run:
Create folder for the corpus and artifacts for any crashes found, then run the fuzzer.

```
mkdir corpus
mkdir artifacts
build/bin/ubpf_fuzzer corpus -artifact_prefix=artifacts/
```

Optionally, add the "-jobs=100" to gather 100 crashes at a time.

This will produce a lot of output that looks like:
```
#529745 REDUCE cov: 516 ft: 932 corp: 442/22Kb lim: 2875 exec/s: 264872 rss: 429Mb L: 50/188 MS: 3 CrossOver-ChangeBit-EraseBytes-
#529814 REDUCE cov: 516 ft: 932 corp: 442/22Kb lim: 2875 exec/s: 264907 rss: 429Mb L: 45/188 MS: 4 ChangeBit-ShuffleBytes-PersAutoDict-EraseBytes- DE: "\005\000\000\000\000\000\000\000"-
#530202 REDUCE cov: 516 ft: 932 corp: 442/22Kb lim: 2875 exec/s: 265101 rss: 429Mb L: 52/188 MS: 3 ChangeByte-ChangeASCIIInt-EraseBytes-
#531224 REDUCE cov: 518 ft: 934 corp: 443/22Kb lim: 2875 exec/s: 265612 rss: 429Mb L: 73/188 MS: 2 CopyPart-PersAutoDict- DE: "\001\000\000\000"-
#531750 REDUCE cov: 518 ft: 934 corp: 443/22Kb lim: 2875 exec/s: 265875 rss: 429Mb L: 45/188 MS: 1 EraseBytes-
#532127 REDUCE cov: 519 ft: 935 corp: 444/22Kb lim: 2875 exec/s: 266063 rss: 429Mb L: 46/188 MS: 2 ChangeBinInt-ChangeByte-
#532246 REDUCE cov: 519 ft: 935 corp: 444/22Kb lim: 2875 exec/s: 266123 rss: 429Mb L: 66/188 MS: 4 ChangeBit-CrossOver-ShuffleBytes-EraseBytes-
#532357 NEW    cov: 520 ft: 936 corp: 445/22Kb lim: 2875 exec/s: 266178 rss: 429Mb L: 55/188 MS: 1 ChangeBinInt-
#532404 REDUCE cov: 520 ft: 936 corp: 445/22Kb lim: 2875 exec/s: 266202 rss: 429Mb L: 57/188 MS: 2 ChangeBit-EraseBytes-
#532486 REDUCE cov: 520 ft: 936 corp: 445/22Kb lim: 2875 exec/s: 266243 rss: 429Mb L: 44/188 MS: 2 EraseByte
```

Eventually it will probably crash and produce a message like:
```
=================================================================
==376403==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000 (pc 0x000000000000 bp 0x7ffca9d3cda0 sp 0x7ffca9d3cb98 T0)
==376403==Hint: pc points to the zero page.
==376403==The signal is caused by a READ memory access.
==376403==Hint: address points to the zero page.
    #0 0x0  (<unknown module>)
    #1 0x50400001a48f  (<unknown module>)

AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: SEGV (<unknown module>)
==376403==ABORTING
MS: 1 ChangeByte-; base unit: cea14e5e2ecdc723b9beb640471a18b4ea529f75
0x28,0x0,0x0,0x0,0xb4,0x50,0x10,0x6a,0x6a,0x4a,0x6a,0x2d,0x2e,0x1,0x0,0x0,0x0,0x0,0x0,0x0,0x4,0x21,0x0,0x0,0x0,0x0,0x95,0x95,0x26,0x21,0xfc,0xff,0xff,0xff,0x95,0x95,0x95,0x95,0x97,0xb7,0x97,0x97,0x0,0x8e,0x0,0x24,
(\000\000\000\264P\020jjJj-.\001\000\000\000\000\000\000\004!\000\000\000\000\225\225&!\374\377\377\377\225\225\225\225\227\267\227\227\000\216\000$
artifact_prefix='artifacts/'; Test unit written to artifacts/crash-7036cbef2b568fa0b6e458a9c8062571a65144e1
Base64: KAAAALRQEGpqSmotLgEAAAAAAAAEIQAAAACVlSYh/P///5WVlZWXt5eXAI4AJA==
```

To triage the crash, post process it with:
```
libfuzzer/split.sh artifacts/crash-7036cbef2b568fa0b6e458a9c8062571a65144e1

Extracting program-7036cbef2b568fa0b6e458a9c8062571a65144e1...
Extracting memory-7036cbef2b568fa0b6e458a9c8062571a65144e1...
Disassembling program-7036cbef2b568fa0b6e458a9c8062571a65144e1...
Program size: 40
Memory size: 2
Disassembled program:
mov32 %r0, 0x2d6a4a6a
jgt32 %r1, %r0, +0
add32 %r1, 0x95950000
jgt32 %r1, 0x9595ffff, -4
exit
Memory contents:
00000000: 0024                                     .$
```

To repro the crash, you can run:
```
build/bin/ubpf_fuzzer artifacts/crash-7036cbef2b568fa0b6e458a9c8062571a65144e1
```

Or you can repro it using ubpf_test:
```
build/bin/ubpf-test --mem artifacts/memory-7036cbef2b568fa0b6e458a9c8062571a65144e1 artifacts/program-7036cbef2b568fa0b6e458a9c8062571a65144e1 --jit
```

