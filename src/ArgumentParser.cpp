

#include "TrafficGenerator/ArgumentParser.h"


ArgumentParser::ArgumentParser(int argc, char *argv[]) : m_Count(argc), m_Arguments(argv) {}

bool ArgumentParser::OptionExists(const std::string &option) const {
    return GetIterator(option) != GetEnd();
}

const char *ArgumentParser::GetOption(const std::string &option) const {
    char **iterator = GetIterator(option);
    char **end = GetEnd();
    if (iterator != end && ++iterator != end)
        return *iterator;
    return nullptr;
}

char **ArgumentParser::GetEnd() const {
    return m_Arguments + m_Count;
}

char **ArgumentParser::GetIterator(const std::string &option) const {
    return std::find(m_Arguments, m_Arguments + m_Count, option);
}