#include <iostream>
#include <boost/asio.hpp>
#include <boost/asio/spawn.hpp>

#include <espi_oob_channel.hpp>

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

//TODO: add a test to see what happens if device file is not present.
int main(){
    boost::asio::io_context io;

    auto oobHandle = espi::EspioobChannel::getHandle(io);
    std::vector<uint8_t> txPayload = {0x0F};
    std::vector<uint8_t> rxPayload(0);
    /*oobHandle->asyncTransact(0x01, 0x01, txPayload, rxPayload,
                            [&](boost::system::error_code e){
                                std::cout << "error =" << e
                                          <<  ", len =" << rxPayload.size() << std::endl;
                                for(std::size_t i = 0; i < rxPayload.size(); i++){
                                    std::cout << "0x" << std::hex << (int)rxPayload[i] << " ";
                                }
                                std::cout << std::endl;
                            });*/
    do_transaction(oobHandle, txPayload, rxPayload);
    io.run();
    std::cout << "Done" << std::endl;

    return 0;
}
