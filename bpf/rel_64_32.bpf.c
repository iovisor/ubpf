// Copyright (c) 2015 Big Switch Networks, Inc
// SPDX-License-Identifier: Apache-2.0

/*
 * Copyright 2023 Will Hawkins
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

static __attribute__((noinline)) __attribute__((section("sec1"))) int
zero()
{
    return 5;
}

static __attribute__((noinline)) __attribute__((section("sec1"))) int
one(int u)
{
    return u;
}

static __attribute__((noinline)) __attribute__((section("sec1"))) int
two()
{
    return zero();
}

__attribute__((section("__main"))) int
three()
{
    return 3;
}

__attribute__((section("__main"))) int
main()
{
    return one(6) + two() + three();
}
