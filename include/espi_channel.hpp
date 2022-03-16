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
#include <vector>

#include <boost/asio.hpp>
#include "linux/aspeed-espi-ioc.h"
#include <sys/ioctl.h>

namespace espi {

enum class channel: uint8_t {
    outOfBound  = 0x21
};

class espi_channel {
public:
    espi_channel(boost::asio::io_context &ioc_, const std::string &device_file_):
        ioc(ioc_), device_file(device_file_) {
    }
protected:
    boost::system::error_code frame_packet(const channel &channel_type,
            std::vector<uint8_t> &packet) noexcept;

    int32_t do_ioctl(int32_t command_code, struct aspeed_espi_ioc & ioctl_data) {
        return 0;
        //return ioctl(this->fd, command_code, &ioctl_data);
    }
private:
    boost::asio::io_context &ioc;
    const std::string device_file;
};

}

