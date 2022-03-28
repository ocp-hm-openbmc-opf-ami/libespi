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

    static std::shared_ptr<EspioobChannel> getHandle(boost::asio::io_context &ioc){
        static std::shared_ptr<EspioobChannel> singleton;
        if(!singleton) {
            singleton = std::make_shared<EspioobChannel>(ioc);
        }
        return singleton;
    }

    void asyncSend(uint8_t smbus_id, uint8_t command_code, const std::vector<uint8_t> &txPayload,
                   SimpleECCallback cb){
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

    void asyncReceive(std::vector<uint8_t> &rxPayload, SimpleECCallback cb) {
        rxPayload.resize(rxPayload.size() + espiHeaderLen + OOBHeaderLen);
        this->doReceive(rxPayload, cb);
    }

    void asyncTransact(uint8_t smbus_id, uint8_t command_code,
                       const std::vector<uint8_t> txPayload,
                       std::vector<uint8_t> &rxPayload, SimpleECCallback cb){
        this->asyncSend(smbus_id, command_code, txPayload,
                        [&,cb](const boost::system::error_code &ec){
                            if(ec){
                                std::cout << "async_send returnd error" << std::endl;
                                cb(ec);
                            } else {
                                this->asyncReceive(rxPayload, cb);
                            }
                        });
    }


private:
    void doSend(std::vector<uint8_t> &txPacket, SimpleECCallback cb){
        struct aspeed_espi_ioc espiIoc;
        struct espi_oob_msg *oobPkt = (struct espi_oob_msg*)(txPacket.data());
        espiIoc.pkt = (uint8_t*)oobPkt;
        espiIoc.pkt_len = txPacket.size();
        if constexpr(DEBUG){
            std::cout << "Tx cycle :0x" << std::hex << std::setfill('0') << std::setw(2)
                      << (int)oobPkt->cyc << ",   "
                      << "tag :0x"  << std::setw(2) <<(int)oobPkt->tag << ",   "
                      << "len :0x" << std::setw(4)
                      << ESPI_LEN((uint8_t)oobPkt->len_h, (uint8_t)oobPkt->len_l)
                      << std::dec << std::endl;
            hexdump(txPacket);
        }
        int rc = this->do_ioctl(ASPEED_ESPI_OOB_PUT_TX, &espiIoc);
        if(rc == 0){
            boost::asio::post(this->ioc, [=](){ cb(boost::system::error_code());});
        } else {
            boost::asio::post(this->ioc, [=](){
                    cb(boost::system::error_code(rc, boost::system::system_category()));
                });
        }
    }

    void doReceive(std::vector<uint8_t> &rxPacket, SimpleECCallback cb, uint8_t retryNum = 0){
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
                    if constexpr (DEBUG) {
                        std::cout << "Rx cycle :0x" << std::hex << std::setfill('0') << std::setw(2)
                                  << (int)oobPkt->cyc << ",   "
                                  << "tag :0x"  << std::setw(2) << (int)oobPkt->tag << ",   "
                                  << "len :0x" << std::setw(4)
                                  << ESPI_LEN((uint8_t)oobPkt->len_h, (uint8_t)oobPkt->len_l)
                                  << std::dec << std::endl;
                    }
                    rxPacket.resize(espiPacketLen);
                    if constexpr (DEBUG) {
                        hexdump(rxPacket);
                    }
                    assert(rxPacket.size() >= OOBSmallestPacketLen);
                    //This assert is only valid till get_tag is in primitive state
                    assert(oobPkt->tag == 0x00);
                    //oobPkt and espiIoc.pkt will be invalid post rotate
                    oobPkt = nullptr;
                    espiIoc.pkt = nullptr;
                    //Convert espi packet in espi oob payload
                    std::rotate(rxPacket.begin(), rxPacket.begin() + espiHeaderLen + OOBHeaderLen,
                                rxPacket.end());
                    rxPacket.resize(OOBPayloadLen);
                    boost::asio::post(this->ioc, [=](){
                            cb(boost::system::error_code());
                        });
                }
                break;
            case EINVAL:
                if(rxPacket.size() >= ASPEED_ESPI_PKT_LEN_MAX){
                    boost::asio::post(this->ioc, [=](){
                        cb(boost::system::error_code(rc, boost::system::system_category()));
                    });
                    return;
                }
                rxPacket.resize(ASPEED_ESPI_PKT_LEN_MAX);
            case EAGAIN:
            case EBUSY:
            case ENODATA:
                ++retryNum;
                std::cout << "Retrying... Fail Count :" << (int)(retryNum) << std::endl;
                if(retryNum >= max_retry){
                    boost::asio::post(this->ioc, [rc ,cb](){
                            cb(boost::system::error_code(rc, boost::system::system_category()));
                        });
                    return;
                }
                this->timer.expires_after(retryDuration);
                this->timer.async_wait([&,retryNum,cb](const boost::system::error_code &){
                        this->doReceive(rxPacket, cb, retryNum);
                });
                break;
            default:
                boost::asio::post(this->ioc, [=](){
                        cb(boost::system::error_code(rc, boost::system::system_category()));
                    });
                break;
        }
    }

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
