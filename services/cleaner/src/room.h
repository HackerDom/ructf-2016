#pragma once 

#include "pass_checker.h"

#include <boost/serialization/base_object.hpp>
#include <boost/serialization/string.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/serialization/utility.hpp>

#include <string>

using TRoomConfiguration = std::vector<unsigned char>;
using TProgramLogs = std::vector<std::pair<std::string, std::string>>;

class TRoom : public TPassChecker {
public:
    TRoom();
    TRoom(std::string& name, std::string& pass, TRoomConfiguration& configuration);

    const std::string& GetName() const;
    const TRoomConfiguration& GetConfiguration() const;
    const TProgramLogs& GetLogs() const;
    void AddLog(const std::string& program_name, const std::string& log);

private:
    friend class boost::serialization::access;
    template<class TArchive>
    void serialize(TArchive& archive, const unsigned int /*version*/) {
        archive & boost::serialization::base_object<TPassChecker>(*this);
        archive & Name;
        archive & Configuration;
        archive & Logs;
    }

private:
    std::string Name;
    TRoomConfiguration Configuration;
    TProgramLogs Logs;
};
