

#pragma once


#include <string>
#include <algorithm>


class ArgumentParser {

public:

    ArgumentParser(int argc, char *argv[]);

    bool OptionExists(const std::string &option) const;

    const char *GetOption(const std::string &option) const;

private:

    char **GetIterator(const std::string &option) const;

    char **GetEnd() const;

    int m_Count;
    char **m_Arguments;
};