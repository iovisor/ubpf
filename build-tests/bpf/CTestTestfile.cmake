# CMake generated Testfile for 
# Source directory: /home/runner/work/ubpf/ubpf/bpf
# Build directory: /home/runner/work/ubpf/ubpf/build-tests/bpf
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(map_TEST_INTERPRET "/home/runner/work/ubpf/ubpf/build-tests/bin/ubpf_test" "/home/runner/work/ubpf/ubpf/build-tests/bpf/map.bpf.o")
set_tests_properties(map_TEST_INTERPRET PROPERTIES  PASS_REGULAR_EXPRESSION "0x0[
]*[
]*\$" _BACKTRACE_TRIPLES "/home/runner/work/ubpf/ubpf/bpf/CMakeLists.txt;64;add_test;/home/runner/work/ubpf/ubpf/bpf/CMakeLists.txt;77;build_bpf;/home/runner/work/ubpf/ubpf/bpf/CMakeLists.txt;0;")
add_test(map_TEST_JIT "/home/runner/work/ubpf/ubpf/build-tests/bin/ubpf_test" "/home/runner/work/ubpf/ubpf/build-tests/bpf/map.bpf.o")
set_tests_properties(map_TEST_JIT PROPERTIES  PASS_REGULAR_EXPRESSION "0x0[
]*[
]*\$" _BACKTRACE_TRIPLES "/home/runner/work/ubpf/ubpf/bpf/CMakeLists.txt;66;add_test;/home/runner/work/ubpf/ubpf/bpf/CMakeLists.txt;77;build_bpf;/home/runner/work/ubpf/ubpf/bpf/CMakeLists.txt;0;")
add_test(rel_64_32_TEST_INTERPRET "/home/runner/work/ubpf/ubpf/build-tests/bin/ubpf_test" "--main-function" "main" "/home/runner/work/ubpf/ubpf/build-tests/bpf/rel_64_32.bpf.o")
set_tests_properties(rel_64_32_TEST_INTERPRET PROPERTIES  PASS_REGULAR_EXPRESSION "0xe[
]*[
]*\$" _BACKTRACE_TRIPLES "/home/runner/work/ubpf/ubpf/bpf/CMakeLists.txt;64;add_test;/home/runner/work/ubpf/ubpf/bpf/CMakeLists.txt;78;build_bpf;/home/runner/work/ubpf/ubpf/bpf/CMakeLists.txt;0;")
add_test(rel_64_32_TEST_JIT "/home/runner/work/ubpf/ubpf/build-tests/bin/ubpf_test" "--main-function" "main" "/home/runner/work/ubpf/ubpf/build-tests/bpf/rel_64_32.bpf.o")
set_tests_properties(rel_64_32_TEST_JIT PROPERTIES  PASS_REGULAR_EXPRESSION "0xe[
]*[
]*\$" _BACKTRACE_TRIPLES "/home/runner/work/ubpf/ubpf/bpf/CMakeLists.txt;66;add_test;/home/runner/work/ubpf/ubpf/bpf/CMakeLists.txt;78;build_bpf;/home/runner/work/ubpf/ubpf/bpf/CMakeLists.txt;0;")
