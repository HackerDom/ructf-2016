#pragma once

#include "command.h"

#include <string>
#include <memory>

namespace {
    enum EParserState {
        EWaitCmd,
        EWaitNumber1,
        EWaitNumber2,
        EError
    };
}

class TCommandParser {
public:
    TCommandParser(const std::string& listing);
    std::unique_ptr<ICommand> GetNext();

private:
    bool GetNum(size_t& num);

private:
    const std::string& Listing;
    size_t Idx;
    EParserState State;
};
