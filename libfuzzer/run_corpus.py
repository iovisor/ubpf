# Copyright (c) uBPF contributors
# SPDX-License-Identifier: MIT

# This script runs two bpf_conformance plugins against a corpus of bpf programs
# and compares the results. It is used to verify that the plugins are equivalent.
# Each plugin consists of a binary and a set of plugin specific options.

import os
import argparse
import subprocess
import shlex

# Maximum size limits in bytes (1MB)
MAX_INSTRUCTIONS_SIZE = 1024 * 1024
MAX_MEMORY_SIZE = 1024 * 1024

# Timeout for plugin execution in seconds
PLUGIN_TIMEOUT = 30

def parse_plugin_options(options_str: str) -> str | list[str]:
    """Parse plugin options string into either a single string or list of options."""
    if not options_str:
        return []
    # Handle quoted string with potential escaped quotes
    if options_str[0] in ["'", '"']:
        quote = options_str[0]
        if len(options_str) >= 2 and options_str[-1] == quote:
            # Remove outer quotes and handle escaped quotes
            return options_str[1:-1].replace(f"\\{quote}", quote)
    # Split by spaces, preserving quoted substrings
    return shlex.split(options_str)

def parse_corpus_file(corpus_file: str) -> tuple[bytes, bytes]:
    """Parse a corpus file into instructions and memory."""
    try:
        with open(corpus_file, 'rb') as f:
            header = f.read(4)
            if len(header) != 4:
                print(f'Invalid file format (header too short): {corpus_file}')
                return None, None
            instructions_length = int.from_bytes(header, byteorder='little')
            if instructions_length <= 0 or instructions_length > MAX_INSTRUCTIONS_SIZE:
                print(f'Invalid instructions length: {instructions_length}')
                return None, None
            instructions = f.read(instructions_length)
            if len(instructions) != instructions_length:
                print(f'Truncated instructions in file: {corpus_file}')
                return None, None
            memory = f.read(MAX_INSTRUCTIONS_SIZE)
            return instructions, memory
    except IOError as e:
        print(f'Error reading file {corpus_file}: {e}')
        return None, None

def run_plugin(plugin_path: str, memory_hex: str, options: str | list[str],
               instructions: bytes, program: str, debug: bool) -> tuple[bytes | None, str | None]:
    """Execute a plugin and return its output and error message if any."""
    if debug:
        print(f'Running plugin: {plugin_path} {memory_hex} {options}')

    try:
        process = subprocess.Popen(
            [plugin_path, memory_hex, options],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)
        output, stderr = process.communicate(input=instructions, timeout=PLUGIN_TIMEOUT)
        if process.returncode != 0:
            return None, f'Plugin failed with error: {stderr.decode()}'
        return output, None
    except subprocess.TimeoutExpired:
        process.kill()
        return None, f'Plugin timed out on {program}'
    except Exception as e:
        return None, f'Error running plugin: {e}'

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
if not os.access(args.plugin_a, os.X_OK):
    print(f'Plugin A is not executable: {args.plugin_a}')
    exit(1)
if not os.path.isfile(args.plugin_b):
    print(f'Plugin B not found: {args.plugin_b}')
    exit(1)
if not os.access(args.plugin_b, os.X_OK):
    print(f'Plugin B is not executable: {args.plugin_b}')
    exit(1)
if not os.path.isdir(args.corpus):
    print(f'Corpus directory not found: {args.corpus}')
    exit(1)
if not os.access(args.corpus, os.R_OK):
    print(f'Corpus directory is not readable: {args.corpus}')
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
    instructions, memory = parse_corpus_file(os.path.join(args.corpus, program))

    # File must contain both instructions, but memory is optional.
    if instructions is None:
        continue

    # Convert the instructions and memory to hex strings.
    instructions_hex = instructions.hex()
    memory_hex = memory.hex()

    if args.debug:
        print(f'Program: {program}')
        print(f'Instructions: {instructions_hex}')
        print(f'Memory: {memory_hex}')

    # Run plugins
    output_a, error_a = run_plugin(args.plugin_a, memory_hex, options_a,
                                  instructions_hex.encode('utf-8'), program, args.debug)
    if error_a:
        print(error_a)
        continue

    output_b, error_b = run_plugin(args.plugin_b, memory_hex, options_b,
                                  instructions_hex.encode('utf-8'), program, args.debug)
    if error_b:
        print(error_b)
        continue

    # Compare the output of the two plugins.
    if output_a != output_b:
        print(f'Mismatch found in program: {program}')
        print(f'Instructions: {instructions_hex}')
        print(f'Memory: {memory_hex}')
        print(f'Output A ({args.plugin_a}): {output_a.decode() if output_a else None}')
        print(f'Output B ({args.plugin_b}): {output_b.decode() if output_b else None}')

    # Print that this program passed.
    print(f'Program: {program} passed.')

