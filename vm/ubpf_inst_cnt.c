/*
 * Copyright 2021 Eideticom, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define _GNU_SOURCE
#include "ubpf_int.h"

#include <unistd.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>

#ifdef __linux__
#include <linux/perf_event.h>

void enable_instruction_count(int fd)
{
    ioctl(fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
}

void disable_instruction_count(int fd)
{
    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
}

int setup_instruction_counter(void)
{
    int fd;

    struct perf_event_attr pe = {
        .type = PERF_TYPE_HARDWARE,
        .size = sizeof(struct perf_event_attr),
        .config = PERF_COUNT_HW_INSTRUCTIONS,
        .disabled = 1,
        .exclude_kernel = 1,
        .exclude_hv = 1,
    };

    fd = syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0);

    return fd;
}

long long get_instruction_count(int fd)
{
    long long count;
    ssize_t rd;

    rd = read(fd, &count, sizeof(long long));
    if (rd != sizeof(long long))
        return -1;

    return count;
}

#else /* __linux__ */

#include <errno.h>

void disable_instruction_count(int fd)
{
    (void)fd;
}

void enable_instruction_count(int fd)
{
    (void)fd;
}

int setup_instruction_counter(void)
{
    errno = ENOTSUP;
    return -1;
}

long long get_instruction_count(int fd)
{
    (void)fd;
    return -1;
}

#endif /* __linux__ */
