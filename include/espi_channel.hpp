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

#include <errno.h>

#include <boost/asio.hpp>
#include <vector>

#include "linux/aspeed-espi-ioc.h"

namespace espi
{

enum class EspiCycle : uint8_t
{
    outOfBound = 0x21
};

constexpr bool DEBUG = true;

void hexdump(const std::vector<uint8_t>& data, const std::string& prefix = "");

typedef std::function<void(const boost::system::error_code&)> SimpleECCallback;
/*
 * EspiChannel abstracts common functionality across all eSPI channel.
 * +----------------+-------------------+
 * | eSPI header    |   eSPI payaload   |
 * +----------------+-------------------+
 * |<------------eSPI packet----------->|
 * |<---3 Bytes---->|
 * Ref Section 5.1 of eSPI Interafce base Specification
 */

class EspiChannel
{
  protected:
    EspiChannel(boost::asio::io_context& ioc_, const std::string& deviceFile) :
        ioc(ioc_), fd(open(deviceFile.c_str(), O_NONBLOCK))
    {
        if (fd < 0)
        {
            throw boost::system::error_code(errno,
                                            boost::system::system_category());
        }
    }

    virtual ~EspiChannel()
    {
        close(fd);
    }

    /* Frames the first three bytes of espi packet.
     */
    boost::system::error_code frame_header(const EspiCycle& cycle_type,
                                           std::vector<uint8_t>& packet,
                                           std::size_t espiPayloadLen) noexcept;

    virtual uint8_t get_tag() = 0;

    /* do_ioctl: performs ioctl. Returns 0 on success errror code on failure
     */
    int do_ioctl(unsigned long command_code,
                 struct aspeed_espi_ioc* ioctl_data) noexcept;

    boost::asio::io_context& ioc;
    int fd;

    static constexpr std::size_t espiHeaderLen = 0x03;
}; // class EspiChannel
} // namespace espi
