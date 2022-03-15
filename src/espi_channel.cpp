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

#include "espi_channel.hpp"
#include "include/aspeed-espi-ioc.h"
#include <errno.h>
#include <fcntl.h>
#include <iostream>
#include <string.h>
#include <sys/ioctl.h>

espi_channel::espi_channel(int *io_context, const char *device_file) {
  io_context = io_context;
  fd = open(device_file, O_RDWR);
  if (fd == -1 && errno == ENOENT) {
    // TO DO - remove print statement and handle by throwing exception
    std::cout << "error in espi_channel constructor" << std::endl;
  }
}

EESPIStatus espi_channel::frame_packet(uint8_t channel_type,
                                       uint8_t *transact_buffer, uint16_t len) {
  if (transact_buffer == NULL) {
    return ESPI_CC_INVALID_REQ;
  }
  struct espi_comm_hdr *espi_hdr = (struct espi_comm_hdr *)(transact_buffer);
  espi_hdr->cyc = channel_type;
  espi_hdr->len_h = (uint8_t)((len >> 8) & 0x0f);
  espi_hdr->len_l = (uint8_t)(len & 0xff);

  return ESPI_CC_SUCCESS;
}

int espi_channel::do_ioctl(unsigned int command,
                           struct aspeed_espi_ioc *value) {
  if (value == NULL) {
    return ESPI_CC_INVALID_REQ;
  }

  int ioctl_ret = ioctl(fd, command, value);
  return ioctl_ret;
}
