# Copyright (c) uBPF contributors
# SPDX-License-Identifier: MIT

# This script runs two bpf_conformance plugins against a corpus of bpf programs
# and compares the results. It is used to verify that the plugins are equivalent.
# Each plugin consists of a binary and a set of plugin specific options.

import os
import argparse
import subprocess

def parse_plugin_options(options_str: str) -> str | list[str]:
    """Parse plugin options string into either a single string or list of options."""
    if options_str and options_str[0] == "'":
        return options_str[1:-1]
    return options_str.split() if options_str else []

# Read the two plugins and their options from the command line.
# Command line arguments are expected to be in the following format:
# ./run_corpus.py --plugin_a <plugin_a> --options_a <options_a> --plugin_b <plugin_b> --options_b <options_b> --corpus <corpus>
# As an example:
# ./run_corpus.py run_corpus.py --plugin_a ./ubpf_plugin --options_a '--jit' --plugin_b ubpf_plugin --options_b '--jit' --corpus corpus
# There is also a debug flag that can be passed to print debug information.

parser = argparse.ArgumentParser(
    description=(
        'Run two bpf_conformance plugins against a corpus of bpf programs and compare the results.'
    )
)
parser.add_argument('--plugin_a', type=str, required=True, help='The first plugin to run.')
parser.add_argument('--options_a', type=str, default='', help='The options for the first plugin.')
parser.add_argument('--plugin_b', type=str, required=True, help='The second plugin to run.')
parser.add_argument('--options_b', type=str, default='', help='The options for the second plugin.')
parser.add_argument('--corpus', type=str, required=True, help='The corpus of bpf programs to run the plugins against.')
parser.add_argument('--debug', action='store_true', help='Print debug information.')
args = parser.parse_args()

if not os.path.isfile(args.plugin_a):
    print(f'Plugin A not found: {args.plugin_a}')
    exit(1)
if not os.path.isfile(args.plugin_b):
    print(f'Plugin B not found: {args.plugin_b}')
    exit(1)
if not os.path.isdir(args.corpus):
    print(f'Corpus directory not found: {args.corpus}')
    exit(1)

# Enumerate the files in the corpus directory.
corpus_files = [f for f in sorted(os.listdir(args.corpus)) if os.path.isfile(os.path.join(args.corpus, f))]
if not corpus_files:
    print(f'No files found in corpus directory: {args.corpus}')
    exit(1)

options_a = parse_plugin_options(args.options_a)
options_b = parse_plugin_options(args.options_b)

# For each file in the corpus:
# 1. Split the corpus file into BPF instructions and memory.
# 2. Convert both program and memory to hex strings with no spaces.
# 3. Run both plugins with the program and memory as input, passing the program as stdin and the memory as the first command line argument followed by any plugin specific options.
# 4. Compare the output of the two plugins. If the output is different, print the program and memory that caused the difference.

for program in corpus_files:
    # Split the program into instructions and memory.
    # Corpus files are binary, with the first 4 bytes representing the number of bytes of instructions and the rest representing the instructions and memory.
    try:
        with open(os.path.join(args.corpus, program), 'rb') as f:
            header = f.read(4)
            if len(header) != 4:
                print(f'Invalid file format (header too short): {program}')
                continue
            instructions_length = int.from_bytes(header, byteorder='little')
            if instructions_length <= 0 or instructions_length > 1024*1024:  # 1MB limit
                print(f'Invalid instructions length: {instructions_length}')
                continue
            instructions = f.read(instructions_length)
            if len(instructions) != instructions_length:
                print(f'Truncated instructions in file: {program}')
                continue
            memory = f.read(1024*1024)  # Read max 1MB of memory
    except IOError as e:
        print(f'Error reading file {program}: {e}')
        continue

    # Convert the instructions and memory to hex strings.
    instructions_hex = instructions.hex()
    memory_hex = memory.hex()

    if args.debug:
        print(f'Program: {program}')
        print(f'Instructions: {instructions_hex}')
        print(f'Memory: {memory_hex}')

    # Run the first plugin.
    if args.debug:
        print(f'Running plugin: {args.plugin_a} {memory_hex} {options_a}')

    try:
        process_a = subprocess.Popen(
            [args.plugin_a, memory_hex, options_a],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)
        output_a, stderr_a = process_a.communicate(input=instructions, timeout=30)
        if process_a.returncode != 0:
            print(f'Plugin A failed with error: {stderr_a.decode()}')
            continue
    except subprocess.TimeoutExpired:
        process_a.kill()
        print(f'Plugin A timed out on {program}')
        continue
    except Exception as e:
        print(f'Error running plugin A: {e}')
        continue

    if args.debug:
        print(f'Output A {output_a}')

    # Run the second plugin.
    if args.debug:
        print(f'Running plugin: {args.plugin_b} {memory_hex} {options_b}')

    try:
        process_b = subprocess.Popen(
            [args.plugin_b, memory_hex, options_b],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)
        output_b, stderr_b = process_b.communicate(input=instructions, timeout=30)
        if process_b.returncode != 0:
            print(f'Plugin B failed with error: {stderr_b.decode()}')
            continue
    except subprocess.TimeoutExpired:
        process_b.kill()
        print(f'Plugin B timed out on {program}')
        continue
    except Exception as e:
        print(f'Error running plugin B: {e}')
        continue
    if args.debug:
        print(f'Output B {output_b}')

    # Compare the output of the two plugins.
    if output_a != output_b:
        print(f'Mismatch found in program: {program}')
        print(f'Memory: {memory_hex}')
        print(f'Output A ({args.plugin_a}): {output_a}')
        print(f'Output B ({args.plugin_b}): {output_b}')
        # Clean up before exit
        for p in [process_a, process_b]:
            try:
                if p.poll() is None:
                    p.kill()
                    p.wait(timeout=5)
            except Exception:
                pass
        exit(1)

    # Ensure processes are properly cleaned up
    for p in [process_a, process_b]:
        try:
            if p.poll() is None:
                p.kill()
                p.wait(timeout=5)
        except Exception as e:
            print(f'Error cleaning up process: {e}')

    # Print that this program passed.
    print(f'Program: {program} passed.')

