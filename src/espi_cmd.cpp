#include <iostream>
#include <getopt.h>
#include <boost/asio.hpp>
#include <boost/asio/spawn.hpp>
#include <string.h>
#include <algorithm>

#include <espi_oob_channel.hpp>

static const char opt_short[] = "hPVOF:";

static const struct option opt_long [] = {
    //Channel
    { "help",           no_argument,        NULL,       'h' },
    { "perif",          no_argument,        NULL,       'P' },
    { "vw",             no_argument,        NULL,       'V' },
    { "oob",            no_argument,        NULL,       'O' },
    { "flash",          no_argument,        NULL,       'F' },
    //eSPI OOB Options
    { "raw-transact",   required_argument,  NULL,       0 },
    { "smbus-slave-id", required_argument,  NULL,       0 },
    { "smbus-command-code",     required_argument,  NULL,       0 },
    { 0, 0, 0, 0 }
};

static void print_usage(int argc, char **argv)
{
    (void)(argc);
    printf(
           "Usage:\n"
           "%s <Channel> [Options]\n"
           "Channel:\n"
           " -h  | --help               Display this help message\n"
           " -P  | --perif              Use eSPI Virtual Wire channel\n"
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

using namespace espi;

class RawTransaction : public std::enable_shared_from_this<RawTransaction>{
public:
    template<typename... Args>
    static void execute(Args&... args){
        auto x = std::shared_ptr<RawTransaction>(new RawTransaction(args...));
        x->start();
    }
    
private:
    RawTransaction(boost::asio::io_context &ioc, uint8_t smbusId, uint8_t smbusCode,
                   const std::vector<uint8_t> &txPayload) :
    ioc(ioc), smbusId(smbusId), smbusCode(smbusCode), txPayload(txPayload),
    rxPayload(1024)
    {
        oobHandle = EspioobChannel::getHandle(ioc);
        std::copy(txPayload.begin(),txPayload.end(), this->txPayload.begin());
        
    }

    void start(){
        oobHandle->asyncTransact(this->smbusId, this->smbusCode,this->txPayload,
                                 this->rxPayload,
                                 std::bind(&RawTransaction::transactCb,shared_from_this(),
                                           std::placeholders::_1));
    }
    void transactCb(const boost::system::error_code &ec){
        if(ec){
            std::cout << "transaction failed with error code :" << ec << std::endl;
            return;
        } else {
            hexdump(this->txPayload, ">>");
            hexdump(this->rxPayload, "<<");
        }
    }
    boost::asio::io_context &ioc;
    const uint8_t smbusId;
    const uint8_t smbusCode;
    EspioobChannel_h oobHandle;
    std::vector<uint8_t> txPayload;
    std::vector<uint8_t> rxPayload;
};

void espioobChannel(boost::asio::io_context &io, int argc, char **argv){
    (void)(io);
    char opt;
    int opt_index = 0;
    std::vector<uint8_t> txPayload;
    uint8_t smbusCode = 0, smbusSlaveId = 0;
    while ((opt=getopt_long(argc, argv, "", opt_long, &opt_index)) != (char)-1) {
        switch(opt){
        case 0:
        {
            if (std::string(opt_long[opt_index].name) == std::string("raw-transact")) {
                #define CHUNK_SIZE 32
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
                        std::cerr << "payload byte must be in range 0x00 to 0xFF" << std::endl;
                        return;
                    }
                    txPayload.push_back(static_cast<uint8_t>(payloadChar));
                }
            } else if(std::string(opt_long[opt_index].name) == std::string("smbus-slave-id")){
                smbusSlaveId = std::stoi(optarg, nullptr, 16);
            }else if(std::string(opt_long[opt_index].name) == std::string("smbus-command-code")){
                smbusCode = std::stoi(optarg, nullptr, 16);
            }
            else {
                std::cerr << "Unknown option found" <<  std::endl;
                print_usage(argc, argv);
                return;
            }
        }
        break;
        default:
            std::cerr << "Unknown option found" <<  std::endl;
            print_usage(argc, argv);
            return;
        }
    }
    if(smbusCode == 0x00 || smbusSlaveId == 0x00){
        std::cerr << "smbus slave id and command code are needed" << std::endl;
        return;
    }
    RawTransaction::execute(io, smbusSlaveId, smbusCode, txPayload);
}

int main(int argc, char** argv){
    boost::asio::io_context io;
    char opt;
    bool dispatched = false;
    while (((opt=getopt_long(argc, argv, opt_short, opt_long, NULL)) != (char)-1) && (!dispatched)) {
    switch(opt){
        case 'h':
            print_usage(argc, argv);
            return 0;
        case 'O':
            espioobChannel(io, argc, argv);
            dispatched = true;
            break;
        default:
            print_usage(argc, argv);
            return -1;
    }
    }

    if(!dispatched){
        std::cout << "Failed to parse eSPI channel" << std::endl;
        print_usage(argc, argv);
        return -1;
    }
    io.run();
    return 0;
}
