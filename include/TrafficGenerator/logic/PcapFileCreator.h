

#pragma once



#include <cstdint>
#include <cstdio>
#include <cstring>
#include <sys/stat.h>


class PcapFileCreator {
public:
    static void createFileFromBytes(const std::string &name, std::uint8_t *stream, std::size_t length);

    static uint8_t *createByteStreamFromFile(const std::string &name, std::size_t size);

    static std::size_t getFileSize(const std::string &name);
};