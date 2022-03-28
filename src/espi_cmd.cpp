#include <iostream>
#include <boost/asio.hpp>
#include <boost/asio/spawn.hpp>

#include <espi_channel.hpp>

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

//TODO: add a test to see what happens if device file is not present.
int main(){
    boost::asio::io_context io;

    auto oobHandle = espi::EspioobChannel::getHandle(io);
    std::vector<uint8_t> txPayload = {0x0F};
    std::vector<uint8_t> rxPayload(32);
    oobHandle->asyncTransact(0x01, 0x01, txPayload, rxPayload,
                            [&](boost::system::error_code e){
                                std::cout << "error =" << e
                                          <<  ", len =" << rxPayload.size() << std::endl;
                                for(std::size_t i = 0; i < rxPayload.size(); i++){
                                    std::cout << "0x" << std::hex << (int)rxPayload[i] << " ";
                                }
                                std::cout << std::endl;
                            });

    io.run();
    std::cout << "Done" << std::endl;

    return 0;
}
