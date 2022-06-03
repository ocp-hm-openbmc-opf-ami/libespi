# libespi: Interface library to facilitate eSPI transactions
libespi provides eSPI (Enhanced Serial Peripheral Interface) APIs which can be used by
applications on BMC (Baseboard Management Controllers) to communicate with other eSPI
devices on platform.

## eSPI channels and supported transactions

 | Channel   | Channel Name        | Posted Cycles             | Non-Posted Cycles           |
 |-----------|---------------------|---------------------------|-----------------------------|
 |  0        | Peripheral          | Memory Write, Completions | Memory Read, I/O Read/Write |
 |  1        | Virtual Wire        | Virtual Wire GET/PUT      | N/A                         |
 |  2        | Out-of-Band Message | SMBus Packet GET/PUT      | N/A                         |
 |  3        | Flash Access        | N/A                       | Flash Read, Write, Erase    |

More details on can be found on [eSPI base specification rev1.0](https://www.intel.com/content/dam/support/us/en/documents/software/chipset-software/327432-004_espi_base_specification_rev1.0_cb.pdf).

# eSPI APIs
* All eSPI APIs mentioned below are in `espi` namespace.

## eSPI OOB Channel APIs
`EspioobChannel` implements eSPI OOB channel. This channel functionality is available through
`espi_oob_channel.hpp` header. Following are major ingredient provided by EspioobChannel.
* `SimpleECCallback` : completion callback handler. `SimpleECCallback` follows
  `std::function<void(const boost::system::error_code&)>` signature.
* `EspioobChannel::getHandle()`: provides eSPI OOB handler object. handler object is a shared_ptr
  referencing EspioobChannel object. `EspioobChannel_h` is shorthand for handler. All eSPI OOB
  transactions have to be done through this handler. User can invoke `getHandle` individually for
  each transaction. User need not to manage lifetime of OOB handler returned by getHandle method.
* `EspioobChannel::asyncTransact(smbusId, commandCode, txPayload, rxPayload, cb, timeout)`: Executes
  asynchronous send followed by receive. This API provides single interface for single request
  followed by single response type transactions.
  Arguments
  * `smbusId` : smbus id of endpoint
  * `commandCode` : smbus command code
  * `txPayload` : eSPI OOB transmit payload. This is equivalent to byte 7 onwards in eSPI OOB
  channel packets.
  * `rxPayload` : This buffer is used for receiving data.
  * `cb` : `SimpleECCallback` object. This callback gets invoked post completion of eSPI OOB
  transaction.
  * `timeout`(optional) : Amount of time to wait between send and receive. This is optional
    argument.

  completion handler is called with boost error_code object. libespi can generate following error
  code objects
  * `boost::asio::error::message_size` : `txPacket` is too large for eSPI OOB Channel
  * `boost::system::error_code(rc, boost::system::system_category())` where `rc` is linux errno
    error code. Following are common codes returned by espi subsystem
    * EINVAL : packet length was found to be invalid
    * EBUSY : Resource is busy even after are all retry attempts
    * ENODATA : No data available even after all retry attemps

  NOTE:
  1. memory backing `txPayload` and `rxPayload` needs to be managed by user in other words
     `txPayload` and `rxPayload` must not be destructed until invocation of callback cb.
  2. `rxPayload` gets modified during transaction regardless of transaction result. Contents
      rxPayload should be used only if error code passed to cb states no error.

  Flow Chart
  
  ![asyncTransact](https://user-images.githubusercontent.com/95036707/170998769-e6cde0bd-ca8a-49ab-ac92-1176e2334752.png)

### Pseudo code example usage
```
#include <espi_oob_channel.hpp>
...
auto oobHandle = espi::EspioobChannel::getHandle();
oobHandle->asyncTransact(0x01/*smbus id*/, 0x02/*smbus command code*/,
                         txPayload/*vector<uint8_t>*/,
                         rxPayload/*vector<uint8_t>*/,
                         [&](const boost::system::error_code&){
                             if(ec){
                                //transaction failed
                                return;
                             }
                             //transaction complete
                         },
                         std::chrono::milliseconds(500));
```
Refer `src/espi_cmd.c` for usage example.

### Limitations
Current implementation of eSPI OOB channel doesn't handle tagging. Hence simultaneous access by more
than one client at a time is not possible.

### espi_cmd
espi_cmd utility is build along with libespi. espi_cmd allows execution of espi transactions from
shell.
```
root@intel-obmc:~# espi_cmd --help
Usage:
espi_cmd <Channel> <Channel> [Channel Options]
Channel:
 -h  | --help               Display this help message
 -P  | --perif              Use eSPI Peripheral channel
 -V  | --vw                 Use eSPI Virtual Wire channel
 -O  | --oob                Use eSPI Out of Bound channel
 -F  | --flash              Use eSPI Flash channel
eSPI OOB Channel Options:
       --smbus-slave-id     smbus slave id
       --smbus-command-code smbus command code
       --raw-transact       Custom raw buffer

```
espi_cmd can be used for sending and receiving raw packets on eSPI OOB Channel. Following example
run gets PCH RTC time.
```
root@intel-obmc:~# espi_cmd -O --smbus-slave-id 0x01 --smbus-command-code 0x02 --raw-transact "0x1d"
>>0x1d
<<0x03 0x02 0x59 0x29 0x05 0x07 0x04 0x03 0x98
```
Content post `>>` and `<<` shows data send to eSPI master and received from eSPI master
respectively. raw packet content should be inside double quotes.
