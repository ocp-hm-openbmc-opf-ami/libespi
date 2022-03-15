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
#include "espi_channel.hpp"
#include <inttypes.h>
#include <stdint.h>

#define MAX_RETRY_COUNT 5

class espi_oob_channel : public espi_channel {
  int retry_count;
  long int wait_duration;
  int fd;

  espi_oob_channel(int *io_context, const char *device_file);
  EESPIStatus frame_packet(uint8_t *transact_buffer, uint16_t len,
                           uint8_t smbus_id, uint8_t command_code,
                           uint8_t *payload, uint16_t payload_len);

public:
  int async_send(uint8_t *transact_buffer, uint16_t len, uint8_t *payload,
                 uint16_t payload_len, uint8_t smbus_id, uint8_t command_code);
  int async_receive(uint8_t *transact_buffer, uint8_t *resp, uint16_t resp_len);
  int transact(uint8_t *transact_buffer, uint16_t len, uint8_t smbus_id,
               uint8_t command_code, uint8_t *payload, uint16_t payload_len,
               uint8_t *resp, uint16_t resp_len);

  static espi_oob_channel &Instance(int *io_context, const char *device_file);
  ~espi_oob_channel();
};
