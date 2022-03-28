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
#include <iostream>
#include <string>
#include <iomanip>
#include <sys/ioctl.h>
#include <cassert>

#include <espi_channel.hpp>

namespace espi {

void hexdump(const std::vector<uint8_t> &data, const std::string &prefix){
    std::cout << prefix ;
    for(auto &i : data){
        std::cout << "0x" << std::hex << std::setfill('0') << std::setw(2) << (int)i << " ";
    }
    std::cout << std::dec << std::endl;
}

boost::system::error_code
EspiChannel::frame_header(const EspiCycle &cycle_type, std::vector<uint8_t> &packet,
                          std::size_t espiPayloadLen) noexcept {
    if(packet.empty()){
        packet.push_back((uint8_t)EspiCycle::outOfBound);
        packet.push_back(((0xF0 & this->get_tag()) |
                           ESPI_LEN_HIGH(espiPayloadLen)));
        packet.push_back(ESPI_LEN_LOW(espiPayloadLen));
    } else {
        if(packet.size() < espiHeaderLen){
            return boost::asio::error::no_buffer_space;
        }
        packet[0] = (uint8_t)cycle_type;
        packet[1] = ((0xF0 & this->get_tag()) | ESPI_LEN_HIGH(espiPayloadLen));
        packet[2] = ESPI_LEN_LOW(espiPayloadLen);
    }
    return boost::system::error_code();
}

int EspiChannel::do_ioctl(unsigned long command_code,
                          struct aspeed_espi_ioc *ioctl_data) noexcept {
    int rc = ioctl(this->fd, command_code, ioctl_data);
    if(rc){
        rc = errno;
        std::cerr << "ioctl error, error code " << rc << std::endl;
        return rc;
    } else {
        return 0;
    }
}
} //namespace espi

