#pragma once 

#include "pass_checker.h"

#include <boost/serialization/base_object.hpp>
#include <boost/serialization/string.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/serialization/utility.hpp>

#include <string>
#include <array>

using TRoomPlan = std::string;
using TProgramLogs = std::vector<std::pair<std::string, std::string>>;

class TRoom : public TPassChecker {
public:
    TRoom();
    TRoom(std::string& name, std::string& pass, TRoomPlan& plan);

    const std::string& GetName() const;
    TRoomPlan& GetPlan();
    const TProgramLogs& GetLogs() const;
    void AddLog(const std::string& program_name, const std::string& log);

private:
    friend class boost::serialization::access;
    template<class TArchive>
    void serialize(TArchive& archive, const unsigned int /*version*/) {
        archive & boost::serialization::base_object<TPassChecker>(*this);
        archive & const_cast<std::string&>(Name);
        archive & Plan;
        archive & Logs;
    }

private:
    const std::string Name;
    TRoomPlan Plan;
    TProgramLogs Logs;
};
