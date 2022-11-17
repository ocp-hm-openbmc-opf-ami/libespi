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

#include "espi_channel.hpp"

#include <boost/asio.hpp>
#include <memory>
#include <vector>

namespace espi
{

const std::string oobDeviceFile = "/dev/aspeed-espi-oob";

class EspioobChannel;
typedef std::shared_ptr<EspioobChannel> EspioobChannel_h;

/*
 * EspioobChannel facilitates eSPI Out of Bound channel transactions.
 * +----------------+-------------------+-------------------+
 * | eSPI header    |   eSPI OOB header |   eSPI OOB payload|
 * +----------------+-------------------+-------------------+
 * |<------------eSPI packet------------------------------->|
 *                  |<----------eSPI OOB packet------------>|
 * |<---3 Bytes---->|<------3 Bytes---->|
 * Ref Section 5.2.3 of eSPI Interafce base Specification.
 */
class EspioobChannel : public EspiChannel
{
  public:
    static EspioobChannel_h getHandle(boost::asio::io_context& ioc)
    {
        static EspioobChannel_h singleton(new EspioobChannel(ioc));
        return singleton;
    }

    void asyncTransact(uint8_t smbusId, uint8_t commandCode,
                       const std::vector<uint8_t>& txPayload,
                       std::vector<uint8_t>& rxPayload, SimpleECCallback cb,
                       const std::chrono::duration<int, std::milli>&
                           transactWaitDuration = defaultTransactWaitDuration);

    void asyncSend(uint8_t smbusId, uint8_t commandCode,
                   const std::vector<uint8_t>& txPayload, SimpleECCallback cb);

    void asyncReceive(std::vector<uint8_t>& rxPayload, SimpleECCallback cb);

  private:
    EspioobChannel(boost::asio::io_context& ioc) :
        EspiChannel(ioc, oobDeviceFile)
    {
    }

    void doSend(std::vector<uint8_t>& txPacket, SimpleECCallback cb);

    void doReceive(std::vector<uint8_t>& rxPacket, SimpleECCallback cb,
                   int retryNum = 0);

    virtual uint8_t getTag()
    {
        // Ordering can allow simontaneous transaction. Refer Section 5.1.2
        // and 5.4 of eSPI specification for more details.
        // TODO: Add this along with some sort queuing to implement ordering.
        return 0x00;
    }

    static constexpr int maxRetry = 3;
    static constexpr std::chrono::duration<int, std::milli>
        defaultRetryWaitDuration = std::chrono::milliseconds(500);

    static constexpr std::chrono::duration<int, std::milli>
        defaultTransactWaitDuration = std::chrono::milliseconds(100);

    static constexpr std::size_t OOBHeaderLen = 0x03;
    static constexpr std::size_t OOBHeaderLenIndex = 0x02;
    static constexpr std::size_t OOBSmallestPacketLen = 0x06;
    static constexpr std::size_t OOBMaxPayloadLen = 0xFF;
};
} // namespace espi
