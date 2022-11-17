/*
// Copyright (c) 2022 Intel Corporation
//
// This software and the related documents are Intel copyrighted
// materials, and your use of them is governed by the express license
// under which they were provided to you ("License"). Unless the
// License provides otherwise, you may not use, modify, copy, publish,
// distribute, disclose or transmit this software or the related
// documents without Intel's prior written permission.
//
// This software and the related documents are provided as is, with no
// express or implied warranties, other than those that are expressly
// stated in the License.
*/

#pragma once

#include <boost/asio.hpp>
#include <vector>

namespace espi
{

constexpr bool DEBUG = false;

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
    EspiChannel(boost::asio::io_context& ioc, const std::string& deviceFile);

    virtual ~EspiChannel()
    {
        close(fd);
    }

    EspiChannel(EspiChannel&) = delete;
    EspiChannel(EspiChannel&&) = delete;
    EspiChannel& operator=(EspiChannel&) = delete;
    EspiChannel& operator=(EspiChannel&&) = delete;

    virtual uint8_t getTag() = 0;

    /* doIoctl: performs ioctl. Returns 0 on success errror code on failure
     */
    int doIoctl(unsigned long commandCode, void* ioctlData) noexcept;

    boost::asio::io_context& ioc;
    int fd;

    static constexpr std::size_t espiHeaderLen = 0x03;
}; // class EspiChannel
} // namespace espi
