

#include "TrafficGenerator/logic/FirewallLayer.h"

FirewallLayer::FirewallLayer(std::uint8_t *data, std::size_t dataLen, pcpp::Layer *prevLayer, pcpp::Packet *packet)
        : Layer(data, dataLen, prevLayer, packet) {
    m_Protocol = FIREWALL;
}

void FirewallLayer::InitFirewallLayer(std::size_t bytesToAllocate) {
    m_DataLen = bytesToAllocate;
    m_Data = new std::uint8_t[bytesToAllocate];
    std::fill(m_Data, m_Data + bytesToAllocate, 0);
    m_Protocol = FIREWALL;

}

FirewallLayer::FirewallLayer() : Layer() {
    InitFirewallLayer(sizeof(FirewallHeader));
}

FirewallLayer::FirewallLayer(FirewallLayer::FirewallOpcodes opcode, FirewallLayer::FirewallTargetFilters targetFilter)
        : Layer() {
    InitFirewallLayer(sizeof(FirewallHeader));
    SetOpcode(opcode);
    SetTargetFilter(targetFilter);


}

void FirewallLayer::SetOpcode(FirewallLayer::FirewallOpcodes opcode) const {
    FirewallHeader *header = GetFirewallHeader();
    header->m_Opcode = opcode;
}

void FirewallLayer::SetTargetFilter(FirewallLayer::FirewallTargetFilters targetFilter) const {
    FirewallHeader *header = GetFirewallHeader();
    header->m_TargetFilter = targetFilter;
}

FirewallLayer::FirewallTargetFilters FirewallLayer::GetTargetFilter() const {
    return (FirewallTargetFilters) GetFirewallHeader()->m_TargetFilter;
}

FirewallLayer::FirewallHeader *FirewallLayer::GetFirewallHeader() const {
    return (FirewallHeader *) m_Data;
}

FirewallLayer::FirewallOpcodes FirewallLayer::GetOpcode() const {
    return (FirewallOpcodes) GetFirewallHeader()->m_Opcode;
}

size_t FirewallLayer::getHeaderLen() const {
    return m_DataLen;
}

void FirewallLayer::parseNextLayer() {}

void FirewallLayer::computeCalculateFields() {}

std::string FirewallLayer::toString() const {
    std::string opcode = "Unknown";
    std::string targetFilter = "Unknown";

    switch(GetOpcode()) {
        case FIREWALL_REQUEST:
            opcode = "Request";
            break;
        case FIREWALL_REPLY:
            opcode = "Reply";
            break;
        default:
            break;
    }

    switch(GetTargetFilter()) {

        case FILE_FILTER:
            targetFilter = "File Filter";
            break;
        case PACKET_FILTER:
            targetFilter = "Packet Filter";
            break;
        default:
            break;
    }

    return "Firewall layer(" + targetFilter + " | " + opcode + ")";

}

pcpp::OsiModelLayer FirewallLayer::getOsiModelLayer() const {
    return pcpp::OsiModelApplicationLayer;
}