#pragma once

#include "room.h"
#include "state.h"
#include "pass_checker.h"

#include <string>

#include <boost/serialization/base_object.hpp>
#include <boost/serialization/string.hpp>

class TProgram : public TPassChecker {
public:
    TProgram();
    TProgram(std::string& name, std::string& pass, std::string& listing);

    const std::string& GetName() const;
    const std::string& GetListing() const;

    void Run(TRoom& room, TProgramState& state) const;

private:
    friend class boost::serialization::access;
    template<class TArchive>
    void serialize(TArchive& archive, const unsigned int /*version*/) {
        archive & boost::serialization::base_object<TPassChecker>(*this);
        archive & const_cast<std::string&>(Name);
        archive & const_cast<std::string&>(Listing);
    }

private:
    const std::string Name;
    const std::string Listing;
};
