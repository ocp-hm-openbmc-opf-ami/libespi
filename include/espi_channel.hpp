/*
// Copyright (c) 2022 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

#pragma once
#include <inttypes.h>
#include <stdint.h>

/* ESPI Status Codes */
typedef enum {
  ESPI_CC_SUCCESS = 0,
  ESPI_CC_INVALID_REQ,
  ESPI_CC_INVALID_LEN,
} EESPIStatus;

class espi_channel {
protected:
  int *io_context, fd;
  espi_channel(int *io_context, const char *device_file);
  EESPIStatus frame_packet(uint8_t channel_type, uint8_t *transact_buffer,
                           uint16_t len);
  int do_ioctl(unsigned int command, struct aspeed_espi_ioc *value);
};
