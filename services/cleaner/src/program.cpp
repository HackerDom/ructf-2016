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

std::string TProgram::Run(const TRoom& room, TProgramState& state) const {
    const auto& configuration = room.GetConfiguration();
    std::unique_ptr<ICommand> command;
    TCommandParser parser(Listing);
    state.Log.resize(Listing.size());

    std::cout << (void *) state.Log.c_str() << std::endl;

    /*
    for (size_t i = 4096; i < 5096; ++i) {
        std::cout << state.Log.c_str()[i];
    }
    std::cout << std::endl;
    */

    while (true) {
        command = parser.GetNext();
        if (!command || !command->Run(state, configuration)) {
            break;
        }
    }

    return state.Log;
}
