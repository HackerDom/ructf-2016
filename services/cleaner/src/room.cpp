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

bool TRoom::CheckHall(const std::string& hall_hex) const {
    auto hall_size{Configuration.size() / 2};
    TRoomConfiguration hall{hall_size};
    boost::algorithm::unhex(hall_hex.begin(), hall_hex.begin() + hall.size() / 16, std::back_inserter(hall));

    return std::equal(hall.begin(), hall.end(), Configuration.begin());
}
