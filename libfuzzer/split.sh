#!/bin/bash

# Split the file name into path and base name
path=$(dirname $1)
base=$(basename $1)

# Get the first 4 bytes from the file (which is the length of the program)
input="$(xxd -p -l 4 $1)"
# Convert from little endian
input="${input:6:2}${input:4:2}${input:2:2}${input:0:2}"

# Convert input from hex string to value
length=$((16#$input))

# Extract the hash part from the file name
hash=$(echo $base | cut -d'-' -f2-)

# Copy the program to a file named program-$hash
echo "Extracting program-$hash..."
dd if=$1 of=$path/program-$hash bs=1 skip=4 count=$length 2> /dev/null

echo "Extracting memory-$hash..."
# Copy the rest to a file named memory-$hash
dd if=$1 of=$path/memory-$hash bs=1 skip=$((4 + $length)) 2> /dev/null

echo "Disassembling program-$hash..."
# Unassembly program using bin/ubpf-disassembler
bin/ubpf-disassembler $path/program-$hash > $path/program-$hash.asm

echo "Program size: $(stat -c %s $path/program-$hash)"
echo "Memory size: $(stat -c %s $path/memory-$hash)"

echo "Disassembled program:"
cat $path/program-$hash.asm

echo "Memory contents:"
xxd $path/memory-$hash
