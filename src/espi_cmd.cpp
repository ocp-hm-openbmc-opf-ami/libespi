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
#include <getopt.h>
#include <string.h>

#include <algorithm>
#include <boost/asio.hpp>
#include <espi_oob_channel.hpp>
#include <iostream>

static const char optShort[] = "hPVOF:";

static const struct option optLong[] = {
    // Channel
    {"help", no_argument, NULL, 'h'},
    {"perif", no_argument, NULL, 'P'},
    {"vw", no_argument, NULL, 'V'},
    {"oob", no_argument, NULL, 'O'},
    {"flash", no_argument, NULL, 'F'},
    // eSPI OOB Options
    {"raw-transact", required_argument, NULL, 0},
    {"smbus-slave-id", required_argument, NULL, 0},
    {"smbus-command-code", required_argument, NULL, 0},
    {0, 0, 0, 0}};

static void printUsage(int argc, char** argv)
{
    (void)(argc);
    printf("Usage:\n"
           "%s <Channel> <Channel> [Channel Options]\n"
           "Channel:\n"
           " -h  | --help               Display this help message\n"
           " -P  | --perif              Use eSPI Peripheral channel\n"
           " -V  | --vw                 Use eSPI Virtual Wire channel\n"
           " -O  | --oob                Use eSPI Out of Bound channel\n"
           " -F  | --flash              Use eSPI Flash channel\n"
           "eSPI OOB Channel Options:\n"
           "       --smbus-slave-id     smbus slave id\n"
           "       --smbus-command-code smbus command code\n"
           "       --raw-transact       Custom raw buffer\n"
           "",
           argv[0]);
}

static constexpr std::size_t defaultRxPayload = 1024;

class RawTransaction : public std::enable_shared_from_this<RawTransaction>
{
  public:
    template <typename... Args>
    static void execute(Args&&... args)
    {
        auto worker =
            std::shared_ptr<RawTransaction>(new RawTransaction(args...));
        worker->start();
    }

  private:
    RawTransaction(boost::asio::io_context& ioc, uint8_t smbusId,
                   uint8_t smbusCode, const std::vector<uint8_t>& txPayload) :
        ioc(ioc),
        smbusId(smbusId), smbusCode(smbusCode), txPayload(txPayload),
        rxPayload(defaultRxPayload)
    {
        oobHandle = espi::EspioobChannel::getHandle(ioc);
    }

    void start()
    {
        oobHandle->asyncTransact(smbusId, smbusCode, txPayload, rxPayload,
                                 std::bind(&RawTransaction::transactCb,
                                           shared_from_this(),
                                           std::placeholders::_1));
    }
    void transactCb(const boost::system::error_code& ec)
    {
        if (ec)
        {
            std::cout << "transaction failed with error code :" << ec << "\n";
            return;
        }
        else
        {
            espi::hexdump(txPayload, ">>");
            espi::hexdump(rxPayload, "<<");
        }
    }
    boost::asio::io_context& ioc;
    const uint8_t smbusId;
    const uint8_t smbusCode;
    espi::EspioobChannel_h oobHandle;
    std::vector<uint8_t> txPayload;
    std::vector<uint8_t> rxPayload;
};

void espioobChannel(boost::asio::io_context& io, int argc, char** argv)
{
    char opt;
    int optIndex = 0;
    std::vector<uint8_t> txPayload;
    int smbusCode = -1, smbusSlaveId = -1;
    while ((opt = getopt_long(argc, argv, "", optLong, &optIndex)) != (char)-1)
    {
        switch (opt)
        {
            case 0: {
                if (std::string(optLong[optIndex].name) ==
                    std::string("raw-transact"))
                {
                    int payload;
                    std::istringstream streamer{std::string(optarg)};
                    streamer >> std::hex;
                    while (streamer.good())
                    {
                        payload = -1;
                        streamer >> payload;
                        if (streamer.fail())
                        {
                            std::cerr << "Inavlid transmit payload"
                                      << std::endl;
                            return;
                        }
                        if (payload < 0x00 || payload > 0xFF)
                        {
                            std::cerr << "payload byte must be in range 0x00 "
                                         "to 0xFF got "
                                      << std::hex << payload << std::dec
                                      << "\n";
                            return;
                        }
                        txPayload.push_back(static_cast<uint8_t>(payload));
                    }
                }
                else if (std::string(optLong[optIndex].name) ==
                         std::string("smbus-slave-id"))
                {
                    smbusSlaveId = std::stoi(optarg, nullptr, 16);
                }
                else if (std::string(optLong[optIndex].name) ==
                         std::string("smbus-command-code"))
                {
                    smbusCode = std::stoi(optarg, nullptr, 16);
                }
                else
                {
                    std::cerr << "Unknown option found\n";
                    printUsage(argc, argv);
                    return;
                }
            }
            break;
            default:
                std::cerr << "Unknown option found\n";
                printUsage(argc, argv);
                return;
        }
    }
    if (smbusCode > 0xFF || smbusCode < 0x00)
    {
        std::cerr << "Invalid smbus command code\n";
    }
    else if (smbusSlaveId > 0xFF || smbusSlaveId < 0x00)
    {
        std::cerr << "Invalid smbus slave id\n";
    }
    else if (txPayload.empty())
    {
        std::cerr << "transmit playload can not be empty\n";
    }
    else
    {
        RawTransaction::execute(io, static_cast<uint8_t>(smbusSlaveId),
                                static_cast<uint8_t>(smbusCode), txPayload);
    }
}

int main(int argc, char** argv)
{
    boost::asio::io_context io;
    char opt;
    bool dispatched = false;
    while (((opt = getopt_long(argc, argv, optShort, optLong, NULL)) !=
            (char)-1) &&
           (!dispatched))
    {
        switch (opt)
        {
            case 'h':
                printUsage(argc, argv);
                return 0;
            case 'O':
                try
                {
                    espioobChannel(io, argc, argv);
                }
                catch (std::exception& e)
                {
                    std::cout << "Failed to execute eSPI OOB channel request :"
                              << e.what() << std::endl;
                    return -1;
                }
                dispatched = true;
                break;
            default:
                printUsage(argc, argv);
                return -1;
        }
    }

    if (!dispatched)
    {
        std::cout << "Failed to parse eSPI channel\n";
        printUsage(argc, argv);
        return -1;
    }
    io.run();
    return 0;
}
