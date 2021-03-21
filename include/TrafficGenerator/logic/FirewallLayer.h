

#pragma once


#include "pcapplusplus/Layer.h"


constexpr auto FIREWALL = 0x400000000;


class FirewallLayer : public pcpp::Layer {

public:

#pragma pack(push, 1)
    struct FirewallHeader {
        std::uint8_t m_Opcode;
        std::uint8_t m_TargetFilter;
    };
#pragma pack(pop)

    enum FirewallOpcodes {
        FIREWALL_REQUEST = 0,
        FIREWALL_REPLY = 1
    };

    enum FirewallTargetFilters {
        FILE_FILTER = 0,
        PACKET_FILTER = 1
    };

public:

    FirewallLayer(std::uint8_t *data, std::size_t dataLen, pcpp::Layer *prevLayer, pcpp::Packet *packet);

    void InitFirewallLayer(std::size_t bytesToAllocate);

    FirewallLayer();

    FirewallLayer(FirewallOpcodes opcode, FirewallTargetFilters targetFilter);

    FirewallHeader *GetFirewallHeader() const;

    FirewallOpcodes GetOpcode() const;

    void SetOpcode(FirewallOpcodes opcode) const;

    FirewallTargetFilters GetTargetFilter() const;

    void SetTargetFilter(FirewallTargetFilters targetFilter) const;

    void parseNextLayer() override;

    size_t getHeaderLen() const override;

    void computeCalculateFields() override;

    std::string toString() const override;

    pcpp::OsiModelLayer getOsiModelLayer() const override;

};