#include <iostream>
#include <getopt.h>
#include <boost/asio.hpp>
#include <boost/asio/spawn.hpp>
#include <string.h>

#include <espi_oob_channel.hpp>

static const char opt_short[] = "hPVOFrtc:";

static const struct option opt_long [] = {
    //Channel
    { "help",           no_argument,        NULL,       'h' },
    { "perif",          no_argument,        NULL,       'P' },
    { "vw",             no_argument,        NULL,       'V' },
    { "oob",            no_argument,        NULL,       'O' },
    { "flash",          no_argument,        NULL,       'F' },
    //Options
    { "temperature",    no_argument,        NULL,       't' },
    { "rtc",            no_argument,        NULL,       'r' },
    { "raw",            required_argument,  NULL,       'c' },
    { 0, 0, 0, 0 }
};

static void print_usage(int argc, char **argv)
{
    (void)(argc);
    printf(
           "Usage:\n"
           "%s <Channel> [Options]\n"
           "Channel:\n"
           " -P  | --perif       Use eSPI Virtual Wire channel\n"
           " -V  | --vw          Use eSPI Virtual Wire channel\n"
           " -O  | --oob         Use eSPI Out of Bound channel\n"
           " -F  | --flash       Use eSPI Flash channel\n"
           "Options:\n"
           " -h | --help         Display this help message\n"
           " -t | --temperature  Fetch PCH Temperature[eSPI OOB]\n"
           " -r | --rtc          Fetch PCH RTC value[eSPI OOB]\n"
           " -c | --raw          Custom raw buffer[eSPI OOB]\n"
           "",
           argv[0]);
}

/*
class PCHTime{
public:
    PCHTime(boost::asio::io_context &io): io(io) { }

    void do_work(boost::asio::yield_context yield){
        auto oobHandle = espi::EspioobChannel(io);
        std::vector<uint8_t> payload = {0x0F};
        std::array<uint8_t, ASPEED_ESPI_PKT_LEN_MAX> recvBuffer;
        boost::system::error_code ec;
        oobHandle.asyncTransact(0x01, 0x01, payload, recvBuffer, yield[ec]);
        std::cout << "Done" << std::endl;
    }
};

private:
    boost::asio::io_context &io;
};
*/

void do_transaction(espi::EspioobChannel_h &oobHandle,
        const std::vector<uint8_t> &txPayload,
        std::vector<uint8_t> &rxPayload){
    std::cout << "[vks][" << __func__ << "][" << __LINE__ << "]" << std::endl;
    std::size_t current_size = rxPayload.size();
    rxPayload.resize(current_size + 1);
    oobHandle->asyncTransact(0x01, 0x01, txPayload, rxPayload,
                            [&](const boost::system::error_code &ec){
                                std::cout << "error =" << ec <<  ", len =" << rxPayload.size()
                                          << std::endl;
                                if(ec){
                                    do_transaction(oobHandle, txPayload, rxPayload);
                                    return;
                                }
                                for(std::size_t i = 0; i < rxPayload.size(); i++){
                                    std::cout << "0x" << std::hex << (int)rxPayload[i] << " ";
                                }
                                std::cout << std::endl;
                            });

}

/* Transmits content of txPayload and places response in rxPayload
 */
/*class RawTransaction{
public:
    RawTransaction(boost::asio::io_context &io, const std::vector<uint8_t> &txPayload,
                   const std::vector<uint8_t> &rxPayload){
    }
};*/

void espioobChannel(boost::asio::io_context &io, int argc, char **argv){
    (void)(io);
    char opt;
#define CHUNK_SIZE 8
    std::vector<uint8_t> txPayload;
    while ((opt=getopt_long(argc, argv, opt_short, opt_long, NULL)) != (char)-1) {
        switch(opt){
        case 't':
            std::cout << "Not implemented\n";
            exit(-1);
            break;
        case 'c':
        {
            char chunk[CHUNK_SIZE];
            int payloadChar;
            std::stringstream ss;
            for(int i = 0;;i++){
                memset(chunk, 0, CHUNK_SIZE);
                strncpy(chunk, optarg + i * (CHUNK_SIZE - 1), (CHUNK_SIZE - 1));
                ss << chunk;
                if(chunk[CHUNK_SIZE - 2] == '\0'){
                    break;
                }
            }
            std::istringstream streamer(ss.str());
            while(streamer.good()){
                streamer >> std::hex;
                streamer >> payloadChar;
                if ( payloadChar < 0x00 || payloadChar > 0xFF){
                    std::cout << "payload byte must be in range 0x00 to 0xFF" << std::endl;
                    return;
                }
                txPayload.push_back(static_cast<uint8_t>(payloadChar));
            }
            break;
        }
        case 'r':
            std::cout << "Not implemented\n";
            exit(-1);
            break;
        default:
            std::cout << "Don't know what to do" << std::endl;
        }
    }

}

int main(int argc, char** argv){
    boost::asio::io_context io;
    char opt;
    while ((opt=getopt_long(argc, argv, opt_short, opt_long, NULL)) != (char)-1) {
    switch(opt){
        case 'h':
            print_usage(argc, argv);
            return 0;
        case 'O':
            espioobChannel(io, argc, argv);
            break;
        default:
            std::cout << "I don't know what you want" << std::endl;
    }
    }

    io.run();
    std::cout << "Done" << std::endl;

    return 0;
}
