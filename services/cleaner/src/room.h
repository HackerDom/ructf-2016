#pragma once 

#include "pass_checker.h"

#include <boost/serialization/base_object.hpp>
#include <boost/serialization/string.hpp>
#include <boost/serialization/vector.hpp>

#include <string>

using TRoomConfiguration = std::vector<unsigned long>;

class TRoom : public TPassChecker {
public:
    TRoom();
    TRoom(std::string& name, std::string& pass, TRoomConfiguration& configuration);

    const std::string& GetName() const;
    const TRoomConfiguration& GetConfiguration() const;
    bool CheckHall(const std::string& hall) const;

private:
    friend class boost::serialization::access;
    template<class TArchive>
    void serialize(TArchive& archive, const unsigned int /*version*/) {
        archive & boost::serialization::base_object<TPassChecker>(*this);
        archive & Name;
        archive & Configuration;
    }

private:
    std::string Name;
    TRoomConfiguration Configuration;
};
