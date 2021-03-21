

#include <string>
#include <iostream>
#include "TrafficGenerator/logic/PcapFileCreator.h"

void PcapFileCreator::createFileFromBytes(const std::string &name, std::uint8_t *stream, std::size_t length) {
    FILE *pcap_file = fopen(name.c_str(), "wb");
    fwrite(stream, 1, length, pcap_file);
    fclose(pcap_file);
}

std::size_t PcapFileCreator::getFileSize(const std::string &name) {
    FILE *file = fopen("unfiltered.pcap", "rb");
    fseek(file, 0, SEEK_END);
    std::size_t fileSize = ftell(file);
    fseek(file, 0, SEEK_SET);
    rewind(file);
    fclose(file);
    return fileSize;
}

uint8_t *PcapFileCreator::createByteStreamFromFile(const std::string &name, std::size_t size) {
    FILE *pcap_file = fopen(name.c_str(), "rb");

    auto *stream = new std::uint8_t[size];

    fread(stream, 1, size, pcap_file);

    return stream;
}