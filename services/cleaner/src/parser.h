#pragma once

#include "command.h"

#include <string>
#include <memory>

class TCommandParser {
public:
    TCommandParser(const std::string& source);
    std::unique_ptr<ICommand> GetNext();

private:
    bool GetNum(size_t& num);

private:
    enum EParserState {
        EWaitCmd,
        EWaitChar,
        EWaitNumber1,
        EWaitNumber2,
        EError
    };

    const std::string& Source;
    size_t Idx;
    EParserState State;
};
