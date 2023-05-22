// Copyright (c) 2022 IO Visor Project
// SPDX-License-Identifier: Apache-2.0

/*
  Copyright (c) 2022-present, IO Visor Project
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#pragma once

#include <libkern/OSByteOrder.h>

#define htole16(value) OSSwapHostToLittleInt16(value)

#define htole32(value) OSSwapHostToLittleInt32(value)

#define htole64(value) OSSwapHostToLittleInt64(value)

#define htobe16(value) OSSwapHostToBigInt16(value)

#define htobe32(value) OSSwapHostToBigInt32(value)

#define htobe64(value) OSSwapHostToBigInt64(value)
