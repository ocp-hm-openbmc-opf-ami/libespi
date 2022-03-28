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
#include <iomanip>
#include <errno.h>

#include "linux/aspeed-espi-ioc.h"

namespace espi {

enum class EspiCycle: uint8_t {
    outOfBound  = 0x21
};

const std::string oobDeviceFile = "/dev/aspeed-espi-oob";
constexpr bool DEBUG = false;

void hexdump(const std::vector<uint8_t> &data, const std::string &prefix = ""){
    std::cout << prefix ;
    for(auto &i : data){
        std::cout << "0x" << std::hex << std::setfill('0') << std::setw(2) << (int)i << " ";
    }
    std::cout << std::dec << std::endl;
}

class EspiChannel {
protected:
    //TODO: Add code to open file or set up file for ioctl usage
    EspiChannel(boost::asio::io_context &ioc_, const std::string &deviceFile):
            ioc(ioc_),fd(open(deviceFile.c_str(), O_NONBLOCK))  {
        if(fd < 0) {
            throw boost::system::error_code(errno, boost::system::system_category());
        }
    }

    virtual ~EspiChannel() {close(fd);}
    boost::system::error_code frame_header(const EspiCycle &cycle_type,
            std::vector<uint8_t> &packet, std::size_t espiPayloadLen) noexcept {
        if(packet.size() == 0){
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

    virtual uint8_t get_tag() = 0;

    int do_ioctl(unsigned long command_code, struct aspeed_espi_ioc *ioctl_data) {
        return ioctl(this->fd, command_code, ioctl_data);
    }

    boost::asio::io_context &ioc;
    int fd;

    static constexpr std::size_t espiHeaderLen = 0x03;
};

void test_method();

//TODO: Don't allow creattion of more than one instance of this class.
class EspioobChannel : public EspiChannel {
public:
    EspioobChannel(boost::asio::io_context &ioc, const std::string deviceFile = oobDeviceFile):
        EspiChannel(ioc, deviceFile), timer(ioc){
        std::cout << "EspioobChannel ctor" << std::endl;
    }
    ~EspioobChannel(){
        std::cout << "EspioobChannel dtor" << std::endl;
    }

    static std::shared_ptr<EspioobChannel> getHandle(boost::asio::io_context &ioc){
        static std::shared_ptr<EspioobChannel> singleton;
        if(!singleton) {
            singleton = std::make_shared<EspioobChannel>(ioc);
        }
        return singleton;
    }

    template <typename WriteHandler>
    void asyncSend(uint8_t smbus_id, uint8_t command_code, const std::vector<uint8_t> &txPayload,
                   WriteHandler cb){
        boost::system::error_code ec;
        std::vector<uint8_t> txPacket;
        if(txPayload.size() > OOBMaxPayloadLen){
            boost::asio::post(this->ioc, [=](){
                    cb(boost::asio::error::message_size);
                });
            return;
        }
        if((ec = this->frame_header(EspiCycle::outOfBound, txPacket,
                                    OOBHeaderLen + txPayload.size()))){
            boost::asio::post(this->ioc, [=](){
                    cb(ec);
                });
            return;
        }
        txPacket.push_back(smbus_id << 1);
        txPacket.push_back(command_code);
        txPacket.push_back(static_cast<uint8_t>(txPayload.size()));

        std::for_each(txPayload.cbegin(), txPayload.cend(),
                      [&](uint8_t i){
                          txPacket.push_back(i);
                      });
        this->doSend(txPacket, cb);
    }

    template <typename ReadHandler>
    void asyncReceive(std::vector<uint8_t> &rxPayload, ReadHandler cb) {
        //User is interested in payload but we are interested in full eSPI packet so we
        //extend it enough to to hold all eSPI headers.
        rxPayload.resize(rxPayload.size() + espiHeaderLen + OOBHeaderLen);
        this->doReceive(rxPayload, cb);
    }

    template <typename ReadHandler>
    void asyncTransact(uint8_t smbus_id, uint8_t command_code,
                       const std::vector<uint8_t> txPayload,
                       std::vector<uint8_t> &rxPayload, ReadHandler cb){
        this->asyncSend(smbus_id, command_code, txPayload, [&](const boost::system::error_code &ec){
            if(ec){
                cb(ec);
            } else {
                this->asyncReceive(rxPayload, cb);
            }
        });
    }


private:
    template <typename WriteHandler>
    void doSend(std::vector<uint8_t> &txPacket, WriteHandler cb){
        struct aspeed_espi_ioc espiIoc;
        struct espi_oob_msg *oobPkt = (struct espi_oob_msg*)(txPacket.data());
        espiIoc.pkt = (uint8_t*)oobPkt;
        espiIoc.pkt_len = txPacket.size();
        if constexpr(DEBUG){
            std::cout << "Tx cycle :" << std::hex << std::setfill('0') << std::setw(2)
                      << (int)oobPkt->cyc << ",   "
                      << "tag :"  << (int)oobPkt->tag << ",   "
                      << "len :" << std::setw(4)
                      << ESPI_LEN((uint8_t)oobPkt->len_h, (uint8_t)oobPkt->len_l)
                      << std::dec << std::endl;
            hexdump(txPacket);
        }
        int rc = this->do_ioctl(ASPEED_ESPI_OOB_PUT_TX, &espiIoc);
        if(rc == 0){
            boost::asio::post(this->ioc, [=](){ cb(boost::system::error_code());});
        } else {
            //TODO: send proper error code
            if(rc == EBUSY){
            }
            boost::asio::post(this->ioc, [=](){ cb(boost::system::error_code());});
        }
    }

    template <typename ReadHandler>
    void doReceive(std::vector<uint8_t> &rxPacket, ReadHandler cb, uint8_t retryNum = 0){
        struct aspeed_espi_ioc espiIoc;
        espiIoc.pkt = (uint8_t*)rxPacket.data();
        espiIoc.pkt_len = rxPacket.size();
        int rc = this->do_ioctl(ASPEED_ESPI_OOB_GET_RX, &espiIoc);
        switch(rc){
            case 0:
                {
                    struct espi_oob_msg *oobPkt = (struct espi_oob_msg*)espiIoc.pkt;
                    std::size_t espiPayloadLen =
                            (std::size_t)ESPI_LEN(oobPkt->len_h, oobPkt->len_l);
                    std::size_t espiPacketLen = espiPayloadLen + espiHeaderLen;
                    std::size_t OOBPayloadLen = espiPayloadLen - OOBHeaderLen;

                    assert(espiPayloadLen  == OOBHeaderLen + 
                            rxPacket[espiHeaderLen + OOBHeaderLenIndex]);
                    rxPacket.resize(espiPacketLen);
                    if constexpr (DEBUG) {
                        std::cout << "Rx cycle :" << std::hex << std::setfill('0') << std::setw(2)
                                  << (int)oobPkt->cyc << ",   "
                                  << "tag :"  << (int)oobPkt->tag << ",   "
                                  << "len :" << std::setw(4)
                                  << ESPI_LEN((uint8_t)oobPkt->len_h, (uint8_t)oobPkt->len_l)
                                  << std::dec << std::endl;
                        hexdump(rxPacket, "");
                    }
                    assert(rxPacket.size() >= OOBSmallestPacketLen);
                    //Convert espi packet in espi oob payload
                    std::rotate(rxPacket.begin(), rxPacket.begin() + espiHeaderLen + OOBHeaderLen,
                                rxPacket.end());
                    rxPacket.resize(OOBPayloadLen);
                    
                    boost::asio::post(this->ioc, [=](){
                            cb(boost::system::error_code());
                        });
                }
                break;
            case EAGAIN:
                if(retryNum >= max_retry){
                    boost::asio::post(this->ioc, [cb](){
                            cb(boost::asio::error::timed_out);
                        });
                    return;
                }
                this->timer.expires_after(retryDuration);
                this->timer.async_wait([&](const boost::system::error_code &){
                        std::cout << "Retry count " << retryNum << std::endl;
                        this->doReceive(rxPacket, cb, retryNum + 1);
                });
                break;
            //TODO: Add other cases that driver returns
            default:
                std::cerr << "Unknown error encountered on eSPI OOB channel receive error code :"
                          << rc << std::endl;
                boost::asio::post(this->ioc, [=](){
                        cb(boost::system::error_code(rc, boost::system::system_category()));
                    });
                break;
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

    static constexpr std::size_t OOBHeaderLen = 0x03;
    static constexpr std::size_t OOBHeaderLenIndex = 0x02;
    static constexpr std::size_t OOBSmallestPacketLen = 0x06;
    static constexpr std::size_t OOBMaxPayloadLen = 0xFF;
};

}

