

#include "TrafficGenerator/logic/DpdkClient.h"

DpdkClient::DpdkClient(DpdkService::DpdkServiceArgs &args) : DpdkService(args) {
    std::cout << "[DpdkClient] constructor" << std::endl;
}

DpdkClient::~DpdkClient() {
    std::cout << "[DpdkClient] destructor" << std::endl;
}

void DpdkClient::HandleServiceStartup() {
    std::cout << "[TrafficGenerator] Server starting..." << std::endl;
}

void DpdkClient::HandleServiceShutdown() {
    std::cout << "[TrafficGenerator] Server closing..." << std::endl;
}

bool DpdkClient::IsDataLinkLayerResponse(const pcpp::Packet &request) {

    auto *ethernetLayer = request.getLayerOfType<pcpp::EthLayer>();
    return ethernetLayer && ethernetLayer->getDestMac() == m_Device->getMacAddress();

}

bool DpdkClient::IsNetworkLayerResponse(const pcpp::Packet &request) {

    if (m_IpAddress.isIPv4() && request.isPacketOfType(pcpp::IPv4)) {
        return m_IpAddress.getIPv4() == request.getLayerOfType<pcpp::IPv4Layer>()->getDstIpAddress();
    }
    if (m_IpAddress.isIPv6() && request.isPacketOfType(pcpp::IPv6)) {
        return m_IpAddress.getIPv6() == request.getLayerOfType<pcpp::IPv6Layer>()->getDstIpAddress();
    }
    return false;

}

bool DpdkClient::IsTransportLayerResponse(const pcpp::Packet &request) const {

    if (request.isPacketOfType(pcpp::TCP)) {
        return m_ServerPortNumber == be16toh(request.getLayerOfType<pcpp::TcpLayer>()->getTcpHeader()->portDst);
    }
    if (request.isPacketOfType(pcpp::UDP)) {
        return m_ServerPortNumber == be16toh(request.getLayerOfType<pcpp::UdpLayer>()->getUdpHeader()->portDst);
    }
    return false;

}

bool DpdkClient::IsApplicationLayerResponse(const pcpp::Packet &request) {

    return request.isPacketOfType(FIREWALL) &&
           FirewallLayer::FirewallOpcodes::FIREWALL_REQUEST == request.getLayerOfType<FirewallLayer>()->GetOpcode();

}

void DpdkClient::Process(const pcpp::Packet &packet) {

    if (IsDataLinkLayerResponse(packet)) {
        if (packet.isPacketOfType(pcpp::ARP)) {

            HandleArp(packet.getLayerOfType<pcpp::ArpLayer>());

        } else if (IsNetworkLayerResponse(packet)) {
            if (packet.isPacketOfType(pcpp::ICMP)) {

                HandleIcmp(packet.getLayerOfType<pcpp::IcmpLayer>());

            } else if (IsTransportLayerResponse(packet)) {
                if (IsApplicationLayerResponse(packet))

                    HandleResponse(packet);

                else if (packet.isPacketOfType(pcpp::DHCP)) {

                    HandleDhcp(packet.getLayerOfType<pcpp::DhcpLayer>());

                }
            }
        }
    }
    else {
        if (m_Logging && !m_SendingEnabled)
            m_LogWriter->writePacket(*packet.getRawPacket());
    }

}

void DpdkClient::HandleResponse(pcpp::Packet packet) {
    std::cout << "RECEIVED FIREWALL PACKET WOOOO" << packet.toString() << std::endl;
    auto *payloadLayer = packet.getLayerOfType<pcpp::PayloadLayer>();
    uint8_t *data = payloadLayer->getPayload();
    size_t length = payloadLayer->getPayloadLen();
    PcapFileCreator::createFileFromBytes("filtered.pcap", data, length);
}

void DpdkClient::EnableSending() {
    std::cout << "Enabled sending" << std::endl;
    m_SendingEnabled = true;

    std::size_t length = PcapFileCreator::getFileSize("unfiltered.pcap");
    std::uint8_t *data = PcapFileCreator::createByteStreamFromFile("unfiltered.pcap", length);

    pcpp::Packet request;
    request.addLayer(new pcpp::EthLayer(m_Device->getMacAddress(), pcpp::MacAddress("08:00:27:d3:51:0a")));
    if (!m_Ipv6Enabled) {
        request.addLayer(new pcpp::IPv4Layer(m_IpAddress.getIPv4(), m_ServerIpAddress.getIPv4()));
    }
    else {
        request.addLayer(new pcpp::IPv6Layer(m_IpAddress.getIPv6(), m_ServerIpAddress.getIPv6()));
    }
    request.addLayer(new pcpp::TcpLayer(1234, m_ServerPortNumber), true);
    request.addLayer(new FirewallLayer(FirewallLayer::FIREWALL_REQUEST, FirewallLayer::PACKET_FILTER), true);
    request.addLayer(new pcpp::PayloadLayer(data, length, false), true);

    std::cout << request.toString() << std::endl;

    std::cout << "sent request" << std::endl;
    m_Device->sendPacket(request, 0);
}

pcpp::Layer *DpdkClient::AllocateRequestDataLinkLayer(const pcpp::Packet &packet) {
    if (packet.isPacketOfType(pcpp::Ethernet)) {
        return new pcpp::EthLayer(m_Device->getMacAddress(), packet.getLayerOfType<pcpp::EthLayer>()->getSourceMac());
    }
    return nullptr;
}

pcpp::Layer *DpdkClient::AllocateRequestNetworkLayer(const pcpp::Packet &packet) {

    if (m_IpAddress.isIPv4() && packet.isPacketOfType(pcpp::IPv4)) {
        return new pcpp::IPv4Layer(m_IpAddress.getIPv4(),
                                   packet.getLayerOfType<pcpp::IPv4Layer>()->getSrcIpAddress());
    }
    if (m_IpAddress.isIPv6() && packet.isPacketOfType(pcpp::IPv6)) {
        return new pcpp::IPv6Layer(m_IpAddress.getIPv6(),
                                   packet.getLayerOfType<pcpp::IPv6Layer>()->getSrcIpAddress());
    }
    return nullptr;

}

pcpp::Layer *DpdkClient::AllocateRequestTransportLayer(const pcpp::Packet &packet) const {

    if (packet.isPacketOfType(pcpp::TCP)) {
        auto *requestTcpLayer = packet.getLayerOfType<pcpp::TcpLayer>();
        return new pcpp::TcpLayer(m_ServerPortNumber, be16toh(requestTcpLayer->getTcpHeader()->portSrc));
    }
    if (packet.isPacketOfType(pcpp::UDP)) {
        auto *requestUdpLayer = packet.getLayerOfType<pcpp::UdpLayer>();
        return new pcpp::UdpLayer(m_ServerPortNumber, be16toh(requestUdpLayer->getUdpHeader()->portSrc));
    }
    return nullptr;

}

pcpp::Layer *DpdkClient::AllocateRequestApplicationLayer(const pcpp::Packet &packet) {
    if (packet.isPacketOfType(FIREWALL)) {
        auto *requestFirewallLayer = packet.getLayerOfType<FirewallLayer>();
        return new FirewallLayer(FirewallLayer::FirewallOpcodes::FIREWALL_REPLY,
                                 requestFirewallLayer->GetTargetFilter());
    }
    return nullptr;
}

void DpdkClient::HandleArp(pcpp::ArpLayer *arpLayer) {
    if (m_IpAddress.isIPv4() && m_IpAddress.isValid()) {
        if (arpLayer->getTargetIpAddr() == m_IpAddress.getIPv4()) {

            pcpp::MacAddress deviceMacAddress = m_Device->getMacAddress();
            pcpp::MacAddress originMacAddress = arpLayer->getSenderMacAddress();

            pcpp::IPv4Address originIpAddress = arpLayer->getSenderIpAddr();

            pcpp::EthLayer responseEthernetLayer(deviceMacAddress, originMacAddress);
            pcpp::ArpLayer responseArpLayer(pcpp::ARP_REPLY, deviceMacAddress, originMacAddress, m_IpAddress.getIPv4(),
                                            originIpAddress);

            pcpp::Packet packet;
            packet.addLayer(&responseEthernetLayer);
            packet.addLayer(&responseArpLayer);

            m_Device->sendPacket(packet, 0);
        }
        else if (arpLayer->getTargetMacAddress() == m_Device->getMacAddress()) {
            m_ServerMacAddress = arpLayer->getSenderMacAddress();
        }
    }
}

void DpdkClient::HandleDhcp(pcpp::DhcpLayer *dhcpLayer) const {
    if (m_DhcpEnabled) {
        auto dhcpMessageType = dhcpLayer->getMesageType();
        switch (dhcpMessageType) {
            case pcpp::DHCP_OFFER:
                //SendRequest();
            case pcpp::DHCP_ACK:
                //assign IP address & local config
            case pcpp::DHCP_NAK:
                //SendDiscover();
            default:
                break;
        }
    }
}

void DpdkClient::HandleIcmp(pcpp::IcmpLayer *icmpLayer) {
    if (m_IpAddress.isValid()) {
        if (m_IpAddress.isIPv4()) {
//            pcpp::IPv4Address deviceAddress = m_IpAddress.getIPv4();
            pcpp::IcmpMessageType icmpMessageType = icmpLayer->getMessageType();
            switch (icmpMessageType) {
                case pcpp::ICMP_INFO_REQUEST:
                    //SendIcmpEchoReply();
                case pcpp::ICMP_TIMESTAMP_REQUEST:
                    //SendIcmpTimestampReply();
                case pcpp::ICMP_ECHO_REQUEST:
                    //SendIcmpInfoRequest();
                case pcpp::ICMP_ADDRESS_MASK_REQUEST:
                    //SendIcmpAddressMaskRequest
                default:
                    break;
            }
        } else if (m_IpAddress.isIPv6()) {
//            pcpp::IPv6Address deviceAddress = m_IpAddress.getIPv6();
        }
    }
}
