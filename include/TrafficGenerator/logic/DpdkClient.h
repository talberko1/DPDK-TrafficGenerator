

#pragma once


#include "DpdkService.h"

#include "FirewallLayer.h"

#include "PcapFileCreator.h"

#include "pcapplusplus/EthLayer.h"
#include "pcapplusplus/ArpLayer.h"
#include "pcapplusplus/IPv4Layer.h"
#include "pcapplusplus/IPv6Layer.h"
#include "pcapplusplus/IcmpLayer.h"
#include "pcapplusplus/TcpLayer.h"
#include "pcapplusplus/UdpLayer.h"
#include "pcapplusplus/DhcpLayer.h"
#include "pcapplusplus/PayloadLayer.h"


class DpdkClient : public DpdkService {
public:

    explicit DpdkClient(DpdkService::DpdkServiceArgs &args);

    ~DpdkClient() override;

    void EnableSending();

protected:

    void HandleServiceStartup() override;

    void HandleServiceShutdown() override;

    void HandleResponse(pcpp::Packet packet);

private:

    void Process(const pcpp::Packet &packet) override;

    bool IsDataLinkLayerResponse(const pcpp::Packet &packet);

    bool IsNetworkLayerResponse(const pcpp::Packet &packet);

    bool IsTransportLayerResponse(const pcpp::Packet &packet) const;

    static bool IsApplicationLayerResponse(const pcpp::Packet &request) ;

    void HandleDhcp(pcpp::DhcpLayer *dhcpLayer) const;

    void HandleArp(pcpp::ArpLayer *arpLayer);

    void HandleIcmp(pcpp::IcmpLayer *icmpLayer);

    pcpp::Layer *AllocateRequestDataLinkLayer(const pcpp::Packet &packet);

    pcpp::Layer *AllocateRequestNetworkLayer(const pcpp::Packet &packet);

    pcpp::Layer *AllocateRequestTransportLayer(const pcpp::Packet &packet) const;

    static pcpp::Layer *AllocateRequestApplicationLayer(const pcpp::Packet &packet);
};