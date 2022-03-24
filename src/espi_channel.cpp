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
#include <iostream>
#include <string>

#include <espi_channel.hpp>

namespace espi {

/* Creates a new std::vector with same content as buf asio::buffer. buffer and vector are using
 * different underlying memory.
 */
std::vector<uint8_t> bufferToVector(const boost::asio::mutable_buffer &buf){
    uint8_t* bufferBegin = static_cast<uint8_t*>(buf.data());
    uint8_t* bufferEnd = bufferBegin + buf.size();
    return std::vector<uint8_t>(bufferBegin, bufferEnd);
}
std::vector<uint8_t> bufferToVector(const boost::asio::const_buffer &buf){
    const uint8_t* bufferBegin = static_cast<const uint8_t*>(buf.data());
    const uint8_t* bufferEnd = bufferBegin + buf.size();
    return std::vector<uint8_t>(bufferBegin, bufferEnd);
}
//TODO: use template mechanism that allows template instantiation for only selected classes and
//use that instead of two copies of bufferToVector method

/* Creates asio::buffer object from std::vector. Both buffer and vector will point to same
 * memory.
 */
boost::asio::mutable_buffer vectorToBuffer(std::vector<uint8_t> &vec){
     return boost::asio::buffer(vec);
}

void test_method(){
    std::cout << "Hell" << std::endl;
}

}
