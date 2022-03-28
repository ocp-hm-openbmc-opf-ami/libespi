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

#include <boost/asio.hpp>
#include <memory>
#include <vector>

#include "espi_channel.hpp"

namespace espi {

const std::string oobDeviceFile = "/dev/aspeed-espi-oob";

class EspioobChannel;
typedef std::shared_ptr<EspioobChannel> EspioobChannel_h;

class EspioobChannel : public EspiChannel {
public:
    EspioobChannel(boost::asio::io_context &ioc, const std::string deviceFile = oobDeviceFile):
        EspiChannel(ioc, deviceFile), timer(ioc){ }
    ~EspioobChannel(){ }

    static EspioobChannel_h getHandle(boost::asio::io_context &ioc){
        static EspioobChannel_h singleton;
        if(!singleton) {
            singleton = std::make_shared<EspioobChannel>(ioc);
        }
        return singleton;
    }

    void asyncSend(uint8_t smbus_id, uint8_t command_code, const std::vector<uint8_t> &txPayload,
                   SimpleECCallback cb);

    void asyncReceive(std::vector<uint8_t> &rxPayload, SimpleECCallback cb);

    void asyncTransact(uint8_t smbus_id, uint8_t command_code,
                       const std::vector<uint8_t> txPayload,
                       std::vector<uint8_t> &rxPayload, SimpleECCallback cb);


private:
    void doSend(std::vector<uint8_t> &txPacket, SimpleECCallback cb);

    void doReceive(std::vector<uint8_t> &rxPacket, SimpleECCallback cb, uint8_t retryNum = 0);

    virtual uint8_t get_tag(){
        //Ordering can allow simontaneous transaction. Refer Section 5.1 of
        //eSPI specification for more details.
        //TODO: If ordering is needed add this in future.
        return 0x00;
    }

    boost::asio::steady_timer timer;
    static constexpr uint8_t max_retry = 3;
    static constexpr boost::asio::chrono::duration<int, std::milli> retryDuration =
            boost::asio::chrono::milliseconds(500);

    static constexpr std::size_t OOBHeaderLen = 0x03;
    static constexpr std::size_t OOBHeaderLenIndex = 0x02;
    static constexpr std::size_t OOBSmallestPacketLen = 0x06;
    static constexpr std::size_t OOBMaxPayloadLen = 0xFF;
};
} //namespace espi
