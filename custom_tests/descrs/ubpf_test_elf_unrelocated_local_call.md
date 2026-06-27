## Test Description

This custom test verifies that the ELF loader correctly resolves an
un-relocated, intra-section bpf-to-bpf call (clang emits these with a
PC-relative `imm` and no relocation entry) when the symbol-table order does
not match ascending section offset.

The crafted relocatable ELF has one executable section containing two
functions whose symbol-table order is the reverse of their section-offset
order:

- `callee` at section offset 0x00: `r0 = 7; exit`
- `entry`  at section offset 0x10: `call callee; exit`  (PC-relative imm, no relocation)

`entry` is the named main function, so the loader pins it to linked PC 0 even
though it sits at section offset 0x10. A loader that relies on link layout
matching the `.o` layout mis-resolves the call; the correct loader rewrites the
call from post-link `landed` values and the program returns 7.

### Expected Behavior

Loading and executing the program returns `0x7`.
