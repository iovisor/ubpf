# Copyright 2015 Big Switch Networks, Inc
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

CFLAGS := -Wall -Werror -Iinc -O2 -g -Wunused-parameter
LDLIBS := -lm

ifeq ($(COVERAGE),1)
CFLAGS += -fprofile-arcs -ftest-coverage
LDFLAGS += -fprofile-arcs
endif

ifeq ($(ASAN),1)
CFLAGS += -fsanitize=address
LDFLAGS += -fsanitize=address
endif

all: libubpf.a test

ubpf_jit_x86_64.o: ubpf_jit_x86_64.c ubpf_jit_x86_64.h

libubpf.a: ubpf_vm.o ubpf_jit_x86_64.o ubpf_loader.o
	ar rc $@ $^

test: test.o libubpf.a

clean:
	rm -f test libubpf.a *.o
