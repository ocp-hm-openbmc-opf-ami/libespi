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

#include <boost/asio.hpp>
#include <cassert>
#include <iomanip>
#include <iostream>

namespace espi
{

void EspioobChannel::asyncSend(uint8_t smbusId, uint8_t commandCode,
                               const std::vector<uint8_t>& txPayload,
                               SimpleECCallback cb)
{
    if (txPayload.size() > OOBMaxPayloadLen)
    {
        boost::asio::post(ioc, [=]() { cb(boost::asio::error::message_size); });
        return;
    }
    boost::system::error_code ec;
    std::vector<uint8_t> txPacket;
    if ((ec = frameHeader(EspiCycle::outOfBound, txPacket,
                          OOBHeaderLen + txPayload.size())))
    {
        boost::asio::post(ioc, [=]() { cb(ec); });
        return;
    }
    txPacket.push_back(smbusId << 1);
    txPacket.push_back(commandCode);
    txPacket.push_back(static_cast<uint8_t>(txPayload.size()));

    std::for_each(txPayload.cbegin(), txPayload.cend(),
                  [&](uint8_t i) { txPacket.push_back(i); });
    doSend(txPacket, cb);
}

void EspioobChannel::asyncReceive(std::vector<uint8_t>& rxPayload,
                                  SimpleECCallback cb)
{
    rxPayload.resize(rxPayload.size() + espiHeaderLen + OOBHeaderLen);
    doReceive(rxPayload, cb);
}
void EspioobChannel::asyncTransact(
    uint8_t smbusId, uint8_t commandCode, const std::vector<uint8_t>& txPayload,
    std::vector<uint8_t>& rxPayload, SimpleECCallback cb,
    const std::chrono::duration<int, std::milli>& transactWaitDuration)
{
    asyncSend(smbusId, commandCode, txPayload,
              [&, cb](const boost::system::error_code& ec) {
                  if (ec)
                  {
                      cb(ec);
                      return;
                  }
                  auto transactWaiter =
                      std::make_unique<boost::asio::steady_timer>(
                          ioc, transactWaitDuration);
                  transactWaiter->async_wait(
                      [&, transactWaiter = std::move(transactWaiter),
                       cb](const boost::system::error_code&) {
                          asyncReceive(rxPayload, cb);
                      });
              });
}
void EspioobChannel::doSend(std::vector<uint8_t>& txPacket, SimpleECCallback cb)
{
    struct aspeed_espi_ioc espiIoc;
    struct espi_oob_msg* oobPkt =
        reinterpret_cast<struct espi_oob_msg*>(txPacket.data());
    espiIoc.pkt = reinterpret_cast<uint8_t*>(oobPkt);
    espiIoc.pkt_len = txPacket.size();
    if constexpr (DEBUG)
    {
        std::cout << "Tx cycle :0x" << std::hex << std::setfill('0')
                  << std::setw(2) << static_cast<int>(oobPkt->cyc) << ",   "
                  << "tag :0x" << std::setw(2) << static_cast<int>(oobPkt->tag)
                  << ",   "
                  << "len :0x" << std::setw(4)
                  << ESPI_LEN(static_cast<uint8_t>(oobPkt->len_h),
                              static_cast<uint8_t>(oobPkt->len_l))
                  << std::dec << "\n";
        hexdump(txPacket);
    }
    int rc = doIoctl(ASPEED_ESPI_OOB_PUT_TX, &espiIoc);
    if (rc == 0)
    {
        boost::asio::post(ioc, [=]() { cb(boost::system::error_code()); });
    }
    else
    {
        boost::asio::post(ioc, [=]() {
            cb(boost::system::error_code(rc, boost::system::system_category()));
        });
    }
}

void EspioobChannel::doReceive(std::vector<uint8_t>& rxPacket,
                               SimpleECCallback cb, int retryNum)
{
    struct aspeed_espi_ioc espiIoc;
    espiIoc.pkt = reinterpret_cast<uint8_t*>(rxPacket.data());
    espiIoc.pkt_len = rxPacket.size();
    int rc = doIoctl(ASPEED_ESPI_OOB_GET_RX, &espiIoc);
    switch (rc)
    {
        case 0: {
            const struct espi_oob_msg* oobPkt =
                reinterpret_cast<const struct espi_oob_msg*>(espiIoc.pkt);
            std::size_t espiPayloadLen = static_cast<std::size_t>(
                ESPI_LEN(oobPkt->len_h, oobPkt->len_l));
            std::size_t espiPacketLen = espiPayloadLen + espiHeaderLen;
            assert(espiPayloadLen ==
                   OOBHeaderLen + rxPacket[espiHeaderLen + OOBHeaderLenIndex]);
            rxPacket.resize(espiPacketLen);
            if constexpr (DEBUG)
            {
                std::cout << "Rx cycle :0x" << std::hex << std::setfill('0')
                          << std::setw(2) << static_cast<int>(oobPkt->cyc)
                          << ",   "
                          << "tag :0x" << std::setw(2)
                          << static_cast<int>(oobPkt->tag) << ",   "
                          << "len :0x" << std::setw(4)
                          << ESPI_LEN(static_cast<uint8_t>(oobPkt->len_h),
                                      static_cast<uint8_t>(oobPkt->len_l))
                          << std::dec << "\n";
                hexdump(rxPacket);
            }
            assert(rxPacket.size() >= OOBSmallestPacketLen);
            // This assert is only valid till getTag is in primitive state
            assert(oobPkt->tag == 0x00);
            // oobPkt and espiIoc.pkt will be invalid post trimming
            oobPkt = nullptr;
            espiIoc.pkt = nullptr;
            rxPacket.erase(rxPacket.begin(),
                           rxPacket.begin() + espiHeaderLen + OOBHeaderLen);
            boost::asio::post(ioc, [=]() { cb(boost::system::error_code()); });
        }
        break;
        case EINVAL:
            if (rxPacket.size() >= ASPEED_ESPI_PKT_LEN_MAX)
            {
                boost::asio::post(ioc, [=]() {
                    cb(boost::system::error_code(
                        rc, boost::system::system_category()));
                });
                return;
            }
            rxPacket.resize(ASPEED_ESPI_PKT_LEN_MAX);
        case EAGAIN:
        case EBUSY:
        case ENODATA: {
            ++retryNum;
            if constexpr (DEBUG)
            {
                std::cout << "Retrying... Fail Count :" << retryNum << "\n";
            }
            if (retryNum >= maxRetry)
            {
                boost::asio::post(ioc, [rc, cb]() {
                    cb(boost::system::error_code(
                        rc, boost::system::system_category()));
                });
                return;
            }
            auto retryWaiter = std::make_unique<boost::asio::steady_timer>(
                ioc, defaultRetryWaitDuration);
            retryWaiter->async_wait([&, retryWaiter = std::move(retryWaiter),
                                     retryNum,
                                     cb](const boost::system::error_code&) {
                doReceive(rxPacket, cb, retryNum);
            });
        }
        break;
        default:
            boost::asio::post(ioc, [=]() {
                cb(boost::system::error_code(rc,
                                             boost::system::system_category()));
            });
            break;
    }
}

} // namespace espi
