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
#include <cassert>
#include <memory>
#include <sys/ioctl.h>
#include <vector>

#include "linux/aspeed-espi-ioc.h"

namespace espi {

enum class EspiCycle: uint8_t {
    outOfBound  = 0x21
};

const std::string oobDeviceFile = "/dev/aspeed-espi-oob";


boost::asio::mutable_buffer vectorToBuffer(std::vector<uint8_t> &);
class EspiChannel {
protected:
    //TODO: Add code to open file or set up file for ioctl usage
    EspiChannel(boost::asio::io_context &ioc_, const std::string &deviceFile):
        ioc(ioc_) {
        this->fd = open(deviceFile.c_str(), O_NONBLOCK);
        if(this->fd < 0){
            //TODO: throw some exception
        }
    }

    virtual ~EspiChannel() {close(fd);}
    boost::system::error_code frame_header(const EspiCycle &cycle_type,
            std::vector<uint8_t> &packet) noexcept {
        assert(packet.size() >= headerLength);
        packet[0] = (uint8_t)cycle_type;
        packet[1] = 0xF0 & this->get_tag();
        packet[1] = 0x0F & (packet.size() - headerLength);
        packet[2] = packet.size() & 0xFF;
        return boost::system::error_code();
    }

    virtual uint8_t get_tag() = 0;

    int do_ioctl(unsigned long command_code, struct aspeed_espi_ioc *ioctl_data) {
        return ioctl(this->fd, command_code, ioctl_data);
    }

    boost::asio::io_context &ioc;
    int fd;

    static constexpr std::size_t headerLength = 0x03;
};

void test_method();

//TODO: Don't allow creattion of more than one instance of this class.
class EspioobChannel : public EspiChannel {
public:
    EspioobChannel(boost::asio::io_context &ioc, const std::string deviceFile = oobDeviceFile):
        EspiChannel(ioc, deviceFile), timer(ioc){
    }
    ~EspioobChannel(){}

    static std::shared_ptr<EspioobChannel> singleton;
    static std::shared_ptr<EspioobChannel> getHandle(boost::asio::io_context &ioc){
        if(!singleton) {
            singleton = std::make_shared<EspioobChannel>(ioc);
        }
        return singleton;
    }

    static void destroyHandle(){
        singleton = nullptr;
    }

    template <typename WriteHandler>
    void asyncSend(uint8_t smbus_id, uint8_t command_code, std::vector<uint8_t> payload,
                   WriteHandler cb){
        std::vector<uint8_t> txPacket;
        //espi header related stuff,
        //TODO: better move and correct this logic in parent's frame buffer. All channels
        //except virtual wire need it.
        txPacket.push_back((uint8_t)EspiCycle::outOfBound);
        txPacket.push_back(((0xF0 & this->get_tag()) | ESPI_LEN_HIGH(3 + payload.size())));
        txPacket.push_back(ESPI_LEN_LOW(3 + payload.size()));
        //setup byte 3 to 5, espi oob specific
        txPacket.push_back(smbus_id << 1);
        txPacket.push_back(command_code);
        txPacket.push_back(static_cast<uint8_t>(payload.size()));

        //get everything from payload
        //TODO: use std::for_each or some iterator like that
        for(auto it = payload.cbegin(); it != payload.cend(); it++){
            txPacket.push_back(*it);
        }
        this->doSend(txPacket, cb);
    }

    template <std::size_t length, typename ReadHandler>
    void asyncReceive(std::array<uint8_t, length> &receiveArray, ReadHandler cb) {
        boost::asio::mutable_buffer receiveBuffer = boost::asio::buffer(receiveArray);
        this->asyncReceive(receiveBuffer, cb);
    }

    template <typename ReadHandler>
    void asyncReceive(boost::asio::mutable_buffer &receiveBuffer, ReadHandler cb) {
        this->doReceive(receiveBuffer, cb);
    }

    template <std::size_t length, typename ReadHandler>
    void asyncTransact(uint8_t smbus_id, uint8_t command_code, std::vector<uint8_t> payload,
                       std::array<uint8_t, length> &receiveArray, ReadHandler cb){
        this->asyncSend(smbus_id, command_code, payload, [&](boost::system::error_code ec){
            std::cout << "Send error code " << ec << std::endl;
            this->asyncReceive(receiveArray, cb);
        });
    }


private:
    template <typename WriteHandler>
    void doSend(std::vector<uint8_t> &txPacket, WriteHandler cb){
        struct aspeed_espi_ioc espiIoc;
        struct espi_oob_msg *oobPkt = (struct espi_oob_msg*)(txPacket.data());
        espiIoc.pkt = (uint8_t*)oobPkt;
        espiIoc.pkt_len = txPacket.size();
        std::cout << "cycle :" << std::hex << (int)oobPkt->cyc << std::endl;
        std::cout << "len_h :" << std::hex << (int)oobPkt->len_h << std::endl;
        std::cout << "tag   :" << std::hex << (int)oobPkt->tag << std::endl;
        std::cout << "len_l :" << std::hex << (int)oobPkt->len_l << std::endl;

        for(std::size_t i = 0; i < txPacket.size(); i++){
            std::cout << "0x" << std::hex << (int)txPacket[i] << " ";
        }
        int rc = this->do_ioctl(ASPEED_ESPI_OOB_PUT_TX, &espiIoc);
        if(rc == 0){
            boost::asio::post(this->ioc, [=](){ cb(boost::system::error_code());});
        } else {
            std::cout << "[vks][" << __func__ << "][" << __LINE__ << "]" << std::endl;
            //TODO: send proper error code
            boost::asio::post(this->ioc, [=](){ cb(boost::system::error_code());});
        }
    }

    template <typename ReadHandler>
    void doReceive(boost::asio::mutable_buffer &receiveBuffer, ReadHandler cb,
                   uint8_t retryNum = 0){
        struct aspeed_espi_ioc espiIoc;
        espiIoc.pkt = (uint8_t*)receiveBuffer.data();
        espiIoc.pkt_len = receiveBuffer.size();
        int rc = this->do_ioctl(ASPEED_ESPI_OOB_GET_RX, &espiIoc);
        //TODO: Better do this via switch
        if(rc == EAGAIN){
            std::cout << "[vks][" << __func__ << "][" << __LINE__ << "]" << std::endl;
            if(retryNum >= max_retry){
                //TODO: call back to caller wtih the right error code.
                //Find the right error code as per asio manual, or create new one if not available
                boost::asio::post(this->ioc, [cb](){cb(boost::system::error_code(), 0);});
                return;
            }
            this->timer.expires_after(retryDuration);
            this->timer.async_wait([&](const boost::system::error_code &error){
                    this->doReceive(receiveBuffer, cb, retryNum + 1);
            });
        } else if(rc == 0) {
            struct espi_oob_msg *oob_pkt = (struct espi_oob_msg*)espiIoc.pkt;
            std::size_t readSize = (size_t)ESPI_LEN(oob_pkt->len_h, oob_pkt->len_l);
            boost::asio::post(this->ioc, [readSize,cb](){cb(boost::system::error_code(), readSize);});
        } else if(rc != 0) {
            std::cout << "[vks][" << __func__ << "][" << __LINE__ << "]" << std::endl;
            //TODO: call the caller wtih an error code that is equivalent to ioctl return
            boost::asio::post(this->ioc, [cb](){cb(boost::system::error_code(), 0);});
        }
    }

    virtual uint8_t get_tag(){
        //eSPI OOB messages can only be one posted transaction at a time Section 5.1.1.
        //As per para 3 of Section 5.1.2 looks like we don't need to worry about orderring ?
        //TODO: If ordering is needed add this in future. For immediate usage single tag is good.
        return 0x00;
    }

    boost::asio::steady_timer timer;
    static constexpr uint8_t max_retry = 3;
    static constexpr boost::asio::chrono::duration<int, std::milli> retryDuration =
            boost::asio::chrono::milliseconds(500);
};

}

