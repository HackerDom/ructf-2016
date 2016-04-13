#include "room.h"

#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>
#include <boost/algorithm/hex.hpp>

#include <algorithm>

TRoom::TRoom() {
}

TRoom::TRoom(std::string& name, std::string& pass, TRoomConfiguration& configuration)
    : TPassChecker(std::move(pass))
    , Name(std::move(name))
    , Configuration(std::move(configuration))
{
}

const std::string& TRoom::GetName() const {
    return Name;
}

const TRoomConfiguration& TRoom::GetConfiguration() const {
    return Configuration;
}

const TProgramLogs& TRoom::GetLogs() const {
    return Logs;
}

void TRoom::AddLog(const std::string& program_name, const std::string& log) {
    Logs.push_back(std::make_pair(program_name, log));
}
