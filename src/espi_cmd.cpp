#include <iostream>
#include <boost/asio.hpp>

#include <espi_channel.hpp>

//TODO: add a test to see what happens if device file is not present.
int main(){
    boost::asio::io_context io;

    auto oobHandle = espi::EspioobChannel(io);
    std::vector<uint8_t> payload = {0x0F};
    std::array<uint8_t, ASPEED_ESPI_PKT_LEN_MAX> recvBuffer;
    oobHandle.asyncTransact(0x01, 0x01, payload, recvBuffer,
                            [&](boost::system::error_code e, std::size_t len){
                                std::cout << "error" << e << std::endl
                                          <<  "len" << len << std::endl;
                                for(std::size_t i = 0; i < len; i++){
                                    std::cout << std::hex << (int)recvBuffer[i] << " ";
                                }
                                std::cout << std::endl;
                            });
    io.run();
    std::cout << "Done" << std::endl;
    return 0;
}
