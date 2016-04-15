#include "program.h"

#include "command.h"
#include "parser.h"

#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/archive/text_iarchive.hpp>
#include <boost/archive/text_oarchive.hpp>

TProgram::TProgram() {
}

TProgram::TProgram(std::string& name, std::string& pass, std::string& listing)
    : TPassChecker(std::move(pass))
    , Name(std::move(name))
    , Listing(std::move(listing))
{
}

const std::string& TProgram::GetName() const {
    return Name;
}

const std::string& TProgram::GetListing() const {
    return Listing;
}

void TProgram::Run(TRoom& room, TProgramState& state) const {
    auto& configuration = room.GetConfiguration();
    std::unique_ptr<ICommand> command;
    TCommandParser parser(Listing);

    while (true) {
        command = parser.GetNext();
        if (!command || !command->Run(state, configuration)) {
            break;
        }
    }
}
