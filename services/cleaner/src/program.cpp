#include "program.h"

#include "command.h"
#include "parser.h"

#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/archive/text_iarchive.hpp>
#include <boost/archive/text_oarchive.hpp>

TProgram::TProgram() {
}

TProgram::TProgram(std::string& name, std::string& pass, std::string& source)
    : TPassChecker(std::move(pass))
    , Name(std::move(name))
    , Source(std::move(source))
{
}

const std::string& TProgram::GetName() const {
    return Name;
}

const std::string& TProgram::GetSource() const {
    return Source;
}

void TProgram::Run(TRoom& room, TProgramState& state) const {
    auto& plan = room.GetPlan();
    std::unique_ptr<ICommand> command;
    TCommandParser parser(Source);

    while (true) {
        command = parser.GetNext();
        if (!command || !command->Run(state, plan)) {
            break;
        }
    }
}
