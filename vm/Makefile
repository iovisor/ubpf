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

CFLAGS := -Wall -Werror -Iinc -O2 -g -Wunused-parameter -fPIC
LDLIBS := -lm

INSTALL ?= install
DESTDIR =
PREFIX ?= /usr/local

ifeq ($(COVERAGE),1)
CFLAGS += -fprofile-arcs -ftest-coverage
LDFLAGS += -fprofile-arcs
endif

ifeq ($(ASAN),1)
CFLAGS += -fsanitize=address,undefined
LDFLAGS += -fsanitize=address,undefined
endif

ifeq ($(DEBUG),1)
CFLAGS += -DDEBUG
endif

all: libubpf.a libubpf.so test

ubpf_jit_x86_64.o: ubpf_config.h ubpf_jit_x86_64.c ubpf_jit_x86_64.h

ubpf_vm.o: ubpf_config.h

test.o: ubpf_config.h

libubpf.a: ubpf_vm.o ubpf_jit_arm64.o ubpf_jit_x86_64.o ubpf_loader.o ubpf_jit.o
	ar rc $@ $^

libubpf.so: ubpf_vm.o ubpf_jit_arm64.o ubpf_jit_x86_64.o ubpf_loader.o ubpf_jit.o
	$(CC) -shared -o $@ $^ $(LDLIBS)

.PHONY: ubpf_config.h
ubpf_config.h:
	echo '#define UBPF_HAS_ELF_H 1' > "inc/ubpf_config.h"

test: test.o libubpf.a

install: all
	$(INSTALL) -d $(DESTDIR)$(PREFIX)/lib
	$(INSTALL) -m 644 libubpf.a $(DESTDIR)$(PREFIX)/lib
	$(INSTALL) -m 644 libubpf.so $(DESTDIR)$(PREFIX)/lib
	$(INSTALL) -d $(DESTDIR)$(PREFIX)/include
	$(INSTALL) -m 644 inc/ubpf.h $(DESTDIR)$(PREFIX)/include
	$(INSTALL) -m 644 inc/ubpf_config.h $(DESTDIR)$(PREFIX)/include

clean:
	rm -f test libubpf.a libubpf.so *.o inc/ubpf_config.h
