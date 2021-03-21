

#pragma once


#include <thread>
#include <atomic>
#include <cstdint>
#include <iostream>

#include "pcapplusplus/MBufRawPacket.h"
#include "pcapplusplus/DpdkDevice.h"
#include "pcapplusplus/DpdkDeviceList.h"
#include "pcapplusplus/PcapFileDevice.h"


constexpr std::uint32_t DEFAULT_DPDK_DEVICE_ID = 0;
constexpr std::uint16_t DEFAULT_RX_AMOUNT = 1;
constexpr std::uint16_t DEFAULT_TX_AMOUNT = 1;
constexpr std::uint16_t DEFAULT_MAX_BURST_SIZE = 64;
constexpr std::uint16_t DEFAULT_MBUF_POOL_SIZE = 16 * 1024 - 1;
constexpr std::uint16_t DEFAULT_FIREWALL_PORT = 5000;


class DpdkService {

public:

    struct DpdkServiceArgs {

    public:

        std::uint32_t m_DpdkPortId = DEFAULT_DPDK_DEVICE_ID;
        std::uint16_t m_RxQueues = DEFAULT_RX_AMOUNT;
        std::uint16_t m_TxQueues = DEFAULT_TX_AMOUNT;
        std::uint16_t m_MaxBurstSize = DEFAULT_MAX_BURST_SIZE;
        std::uint16_t m_MbufPoolSize = DEFAULT_MBUF_POOL_SIZE;
        std::uint16_t m_ServerPortNumber = DEFAULT_FIREWALL_PORT;
        bool m_DhcpEnabled = false;
        bool m_Ipv6Enabled = false;
        std::string m_ServerIpAddress;
        std::string m_ClientIpAddress;
        bool m_Logging = true;

    };

    class DpdkInitializationError : public std::runtime_error {
    public:

        DpdkInitializationError();
    };

    class UnknownDeviceException : public std::runtime_error {
    public:

        explicit UnknownDeviceException(std::uint32_t deviceId);
    };

    class MultiQueueException : public std::runtime_error {
    public:

        MultiQueueException(std::uint16_t rxQueues, std::uint16_t txQueues);
    };

    class InvalidIpAddressException : public std::runtime_error {
    public:

        explicit InvalidIpAddressException(const std::string &address);
    };

    class EmptyLogFileNameException : public std::runtime_error {
    public:

        explicit EmptyLogFileNameException();
    };

    class LogFileException : public std::runtime_error {
    public:

        explicit LogFileException(const std::string &logFileName);
    };

    explicit DpdkService(DpdkServiceArgs &args);

    virtual ~DpdkService();

    void Start();

    bool Running();

    void Close();

private:

    void Run();

protected:

    pcpp::DpdkDevice *m_Device;
    std::atomic<bool> m_Running;
    std::thread m_ServiceThread;
    std::uint16_t m_MaxBurstSize;
    pcpp::MBufRawPacket **m_RawPackets;

    bool m_DhcpEnabled;
    bool m_Ipv6Enabled;

    pcpp::MacAddress m_ServerMacAddress;
    pcpp::IPAddress m_ServerIpAddress;
    std::uint16_t m_ServerPortNumber;

    pcpp::IPAddress m_IpAddress;
    bool m_Logging;

    pcpp::PcapFileWriterDevice *m_LogWriter;
    pcpp::PcapFileWriterDevice *m_FilteredLogWriter;
    std::atomic<bool> m_SendingEnabled;


    virtual void HandleServiceStartup() = 0;

    void HandleServiceRunning();

    virtual void HandleServiceShutdown() = 0;

    virtual void Process(const pcpp::Packet &packet) = 0;
};