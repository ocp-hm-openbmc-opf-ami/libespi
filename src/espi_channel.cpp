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

#include <sys/ioctl.h>

#include <cassert>
#include <espi_channel.hpp>
#include <espi_channel_internal.hpp>
#include <iomanip>
#include <iostream>
#include <string>

#define TAG(tag) (0xF0 & ((tag) << 0x04))

namespace espi
{

void hexdump(const std::vector<uint8_t>& data, const std::string& prefix)
{
    std::cout << prefix;
    for (auto& i : data)
    {
        std::cout << "0x" << std::hex << std::setfill('0') << std::setw(2)
                  << static_cast<int>(i) << " ";
    }
    std::cout << std::dec << "\n";
}

EspiChannel::EspiChannel(boost::asio::io_context& ioc,
                         const std::string& deviceFile) :
    ioc(ioc),
    fd(open(deviceFile.c_str(), O_NONBLOCK))
{
    if (fd < 0)
    {
        throw boost::system::error_code(errno,
                                        boost::system::system_category());
    }
}

boost::system::error_code frameHeader(const EspiCycle& cycleType, uint8_t tag,
                                      std::vector<uint8_t>& packet,
                                      const std::size_t espiPayloadLen) noexcept
{
    if (!packet.empty())
    {
        return boost::asio::error::message_size;
    }
    packet.push_back(static_cast<uint8_t>(cycleType));
    packet.push_back((TAG(tag) | ESPI_LEN_HIGH(espiPayloadLen)));
    packet.push_back(ESPI_LEN_LOW(espiPayloadLen));
    return boost::system::error_code();
}

int EspiChannel::doIoctl(unsigned long commandCode, void* ioctlData) noexcept
{
    if (!ioctlData)
    {
        return EINVAL;
    }
    int rc = ioctl(fd, commandCode, ioctlData);
    if (rc)
    {
        rc = errno;
        if constexpr (DEBUG)
        {
            std::cerr << "ioctl error, error code " << rc << "\n";
        }
    }
    return rc;
}
} // namespace espi
