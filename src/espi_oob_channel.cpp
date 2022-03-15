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

#include "espi_oob_channel.hpp"

#include "include/aspeed-espi-ioc.h"
#include <string.h>
#include <sys/ioctl.h>

#define ESPI_OOB_MSG 0x21

#define BMC_ESPI_ADDR 0x0F

struct smbus_comm_hdr {
  uint8_t dest_slave_addr;
  uint8_t cmd;
  uint8_t len;
  uint8_t source_slave_addr;
} __attribute__((packed));

espi_oob_channel::espi_oob_channel(int *io_context, const char *device_file)
    : espi_channel(io_context, device_file) {
  retry_count = 0;
  wait_duration = 0;
}

espi_oob_channel &espi_oob_channel::Instance(int *io_context,
                                             const char *device_file) {
  static espi_oob_channel obj(io_context, device_file);
  return obj;
}

EESPIStatus espi_oob_channel::frame_packet(uint8_t *transact_buffer,
                                           uint16_t len, uint8_t smbus_id,
                                           uint8_t command_code,
                                           uint8_t *payload,
                                           uint16_t payload_len) {
  if (transact_buffer == NULL) {
    return ESPI_CC_INVALID_REQ;
  }

  uint8_t hdr_len =
      sizeof(struct espi_comm_hdr) + sizeof(struct smbus_comm_hdr);
  if (len <= hdr_len) {
    return ESPI_CC_INVALID_LEN;
  }

  espi_channel::frame_packet(ESPI_OOB_MSG, transact_buffer,
                             (uint16_t)(len - sizeof(struct espi_comm_hdr)));

  struct smbus_comm_hdr *smbus_hdr = (struct smbus_comm_hdr *)(transact_buffer);
  smbus_hdr->dest_slave_addr = smbus_id;
  smbus_hdr->cmd = command_code;
  smbus_hdr->len = (uint8_t)(len - hdr_len + 1);
  smbus_hdr->source_slave_addr = BMC_ESPI_ADDR;

  if (payload != NULL) {
    memcpy((transact_buffer + hdr_len), payload, payload_len);
  }
  return ESPI_CC_SUCCESS;
}

int espi_oob_channel::async_send(uint8_t *transact_buffer, uint16_t len,
                                 uint8_t *payload, uint16_t payload_len,
                                 uint8_t smbus_id, uint8_t command_code) {
  if (fd < 0) {
    return -1;
  }

  if (transact_buffer == NULL || payload == NULL) {
    return ESPI_CC_INVALID_REQ;
  }

  uint8_t hdr_len =
      sizeof(struct espi_comm_hdr) + sizeof(struct smbus_comm_hdr);
  uint32_t data_len = hdr_len;

  if (len < hdr_len) {
    return ESPI_CC_INVALID_LEN;
  }

  if (payload != NULL) {
    if (payload_len <= 0) {
      return ESPI_CC_INVALID_LEN;
    } else {
      data_len += payload_len;
    }
  }

  if (len < data_len) {
    return ESPI_CC_INVALID_REQ;
  }

  EESPIStatus ret = ESPI_CC_SUCCESS;
  if (frame_packet(transact_buffer, (uint16_t)data_len, smbus_id, command_code,
                   payload, payload_len) != ESPI_CC_SUCCESS) {
    return ESPI_CC_INVALID_REQ;
  }

  struct aspeed_espi_ioc espi_ioc;
  espi_ioc.pkt = transact_buffer;
  espi_ioc.pkt_len = data_len;
  int ioctl_ret = do_ioctl(ASPEED_ESPI_OOB_PUT_TX, &espi_ioc);
  if (ioctl_ret < 0) {
    return ioctl_ret;
  }

  return ret;
}

int espi_oob_channel::async_receive(uint8_t *transact_buffer, uint8_t *resp,
                                    uint16_t resp_len) {
  if (fd < 0 || transact_buffer == NULL || resp == NULL) {
    return ESPI_CC_INVALID_REQ;
  }

  struct espi_comm_hdr *espi_hdr = (struct espi_comm_hdr *)(transact_buffer);
  uint16_t len = (uint16_t)((espi_hdr->len_h << 8) | (espi_hdr->len_l & 0xff));
  if (len <= 0) {
    return ESPI_CC_INVALID_LEN;
  }

  EESPIStatus ret = ESPI_CC_SUCCESS;

  struct aspeed_espi_ioc espi_ioc;
  espi_ioc.pkt = transact_buffer;
  espi_ioc.pkt_len = (uint32_t)len;

  int ioctl_ret = do_ioctl(ASPEED_ESPI_OOB_GET_RX, &espi_ioc);
  if (ioctl_ret < 0) {
    return ret;
  }

  uint8_t hdr_len =
      sizeof(struct espi_comm_hdr) + sizeof(struct smbus_comm_hdr);
  if (espi_ioc.pkt_len <= hdr_len) {
    return ESPI_CC_INVALID_LEN;
  }

  struct espi_comm_hdr *res_espi_hdr = (struct espi_comm_hdr *)(espi_ioc.pkt);

  resp_len = (uint16_t)(((res_espi_hdr->len_h << 8) | res_espi_hdr->len_l) -
                        (uint8_t)(sizeof(struct smbus_comm_hdr)));

  if (resp_len > 0) {
    memcpy(resp, (espi_ioc.pkt + hdr_len), resp_len);
  }
  return ret;
}

int espi_oob_channel::transact(uint8_t *transact_buffer, uint16_t len,
                               uint8_t smbus_id, uint8_t command_code,
                               uint8_t *payload, uint16_t payload_len,
                               uint8_t *resp, uint16_t resp_len) {
  if (fd < 0) {
    return -1;
  }

  if (transact_buffer == NULL || payload == NULL) {
    return ESPI_CC_INVALID_REQ;
  }

  uint8_t hdr_len =
      sizeof(struct espi_comm_hdr) + sizeof(struct smbus_comm_hdr);
  uint32_t data_len = hdr_len;

  if (len < hdr_len) {
    return ESPI_CC_INVALID_LEN;
  }
  if (payload != NULL) {
    if (payload_len <= 0) {
      return ESPI_CC_INVALID_LEN;
    } else {
      data_len += payload_len;
    }
  }

  if (len < data_len) {
    return ESPI_CC_INVALID_REQ;
  }

  EESPIStatus ret = ESPI_CC_SUCCESS;
  if (frame_packet(transact_buffer, (uint16_t)data_len, smbus_id, command_code,
                   payload, payload_len) != ESPI_CC_SUCCESS) {
    return ESPI_CC_INVALID_REQ;
  }

  struct aspeed_espi_ioc espi_ioc;
  espi_ioc.pkt = transact_buffer;
  espi_ioc.pkt_len = data_len;
  int ioctl_ret = do_ioctl(ASPEED_ESPI_OOB_PUT_TX, &espi_ioc);
  if (ioctl_ret < 0) {
    return ioctl_ret;
  }

  ioctl_ret = do_ioctl(ASPEED_ESPI_OOB_GET_RX, &espi_ioc);
  if (ioctl_ret < 0) {
    return ret;
  }

  if (espi_ioc.pkt == NULL) {
    return -1;
  }

  struct espi_comm_hdr *espi_hdr = (struct espi_comm_hdr *)(espi_ioc.pkt);
  resp_len = (uint16_t)(((espi_hdr->len_h << 8) | espi_hdr->len_l) -
                        (uint8_t)(sizeof(struct smbus_comm_hdr)));
  if (resp_len > 0) {
    memcpy(resp, (espi_ioc.pkt + hdr_len), resp_len);
  }
  return ret;
}

espi_oob_channel::~espi_oob_channel() {}
