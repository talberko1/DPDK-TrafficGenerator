

#include "TrafficGenerator/logic/DpdkService.h"


DpdkService::DpdkInitializationError::DpdkInitializationError() : std::runtime_error("DPDK Initialization failed") {}

DpdkService::UnknownDeviceException::UnknownDeviceException(std::uint32_t deviceId) : std::runtime_error(
        "Unknown DPDK port id #" + std::to_string(deviceId)) {}

DpdkService::MultiQueueException::MultiQueueException(std::uint16_t rxQueues, std::uint16_t txQueues)
        : std::runtime_error(
        "Failed to open " + std::to_string(rxQueues) + " RX queues and " + std::to_string(txQueues) + " TX queues") {}

DpdkService::InvalidIpAddressException::InvalidIpAddressException(const std::string &address) : std::runtime_error(
        "Invalid IP Address: " + address) {}

DpdkService::EmptyLogFileNameException::EmptyLogFileNameException() : std::runtime_error(
        "Logging is enabled yet log file name is empty") {}

DpdkService::LogFileException::LogFileException(const std::string &logFileName) : std::runtime_error(
        "Could not open the log file" + logFileName + " for writing") {}

DpdkService::DpdkService(DpdkServiceArgs &args) : m_Running(false), m_MaxBurstSize(args.m_MaxBurstSize),
                                                  m_DhcpEnabled(args.m_DhcpEnabled),
                                                  m_Ipv6Enabled(args.m_Ipv6Enabled),
                                                  m_ServerIpAddress(args.m_ServerIpAddress),
                                                  m_ServerPortNumber(args.m_ServerPortNumber),
                                                  m_IpAddress(args.m_ClientIpAddress),
                                                  m_Logging(args.m_Logging),
                                                  m_SendingEnabled(false) {
    std::cout << "[DpdkService] Initializing service..." << std::endl;
    bool dpdkInitialized = pcpp::DpdkDeviceList::initDpdk(pcpp::getCoreMaskForAllMachineCores(),
                                                          args.m_MbufPoolSize);
    if (!dpdkInitialized)
        throw DpdkInitializationError();

    std::cout << "[DpdkService] Activating DPDK device..." << std::endl;
    m_Device = pcpp::DpdkDeviceList::getInstance().getDeviceByPort(args.m_DpdkPortId);
    if (!m_Device)
        throw UnknownDeviceException(args.m_DpdkPortId);
    if (!m_Device->openMultiQueues(args.m_RxQueues, args.m_TxQueues))
        throw MultiQueueException(args.m_RxQueues, args.m_TxQueues);
    std::cout << "[DpdkService] Successfully activated DPDK device!" << std::endl;

    std::cout << "[DpdkService] Allocating " << m_MaxBurstSize * sizeof(pcpp::MBufRawPacket *) << " bytes."
              << std::endl;
    m_RawPackets = static_cast<pcpp::MBufRawPacket **>(::operator new(m_MaxBurstSize * sizeof(pcpp::MBufRawPacket *)));

    if (!m_RawPackets)
        throw std::bad_alloc();

    if (!m_ServerIpAddress.isValid()) {
        throw InvalidIpAddressException(args.m_ClientIpAddress);
    }

    if (!m_IpAddress.isValid()) {
        throw InvalidIpAddressException(args.m_ClientIpAddress);
    }

    std::cout << "[DpdkService] IP Address: " << m_IpAddress.toString() << std::endl;
    std::cout << "[DpdkService] MAC Address: " << m_Device->getMacAddress().toString() << std::endl;

    if (m_Logging) {
//        if (args.m_LogFileName.empty())
//            throw EmptyLogFileNameException();

//        m_LogFileName = args.m_LogFileName;
//        m_FilteredLogFileName = args.m_FilteredLogFileName;

        m_LogWriter = new pcpp::PcapFileWriterDevice("filtered.pcap");
        m_FilteredLogWriter = new pcpp::PcapFileWriterDevice("unfiltered.pcap");
        if (!m_LogWriter->open()) {
            std::cerr << "Could not open " << "filtered.pcap" << "for writing" << std::endl;
            throw LogFileException("filtered.pcap");
        }
        if (!m_FilteredLogWriter->open()) {
            std::cerr << "Could not open " << "unfiltered.pcap" << "for writing" << std::endl;
            throw LogFileException("unfiltered.pcap");
        }
    }

    std::fill(m_RawPackets, m_RawPackets + m_MaxBurstSize, nullptr);
}

DpdkService::~DpdkService() {
    if (m_Device->isOpened()) {
        std::cout << "[DpdkService] Closing DPDK device..." << std::endl;
        m_Device->close();
    }

    std::cout << "[MBuf] Deallocating " << m_MaxBurstSize * sizeof(pcpp::MBufRawPacket *) << " bytes." << std::endl;
    ::operator delete(m_RawPackets, m_MaxBurstSize * sizeof(pcpp::MBufRawPacket *));
}

void DpdkService::HandleServiceRunning() {
    std::uint16_t received = m_Device->receivePackets(m_RawPackets, m_MaxBurstSize, 0);
    for (std::uint16_t i = 0; i < received; i++) {
        pcpp::Packet packet(m_RawPackets[i]);
        Process(packet);
    }
}

void DpdkService::Start() {
    if (!m_Running) {
        HandleServiceStartup();
        m_Running = true;
        m_ServiceThread = std::thread(&DpdkService::Run, this);
    }
}

bool DpdkService::Running() {
    return m_Running;
}

void DpdkService::Run() {
    while (m_Running) {
        HandleServiceRunning();
    }
}

void DpdkService::Close() {
    if (m_Running) {
        m_Running = false;
        if (m_ServiceThread.joinable())
            m_ServiceThread.join();
        HandleServiceShutdown();
    }
}

