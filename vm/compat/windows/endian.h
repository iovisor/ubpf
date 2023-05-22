// Copyright (c) 2022 IO Visor Project
// SPDX-License-Identifier: Apache-2.0

/*
  Copyright (c) 2022-present, IO Visor Project
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#pragma once

#include <Winsock2.h>

#define htole16(value) (value)

#define htole32(value) (value)

#define htole64(value) (value)

#define htobe16(value) htons(value)

#define htobe32(value) htonl(value)

#define htobe64(value) htonll(value)
