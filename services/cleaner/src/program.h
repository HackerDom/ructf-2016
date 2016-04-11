#pragma once

#include "room.h"
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

    std::string Run(const TRoom& room) const;

private:
    friend class boost::serialization::access;
    template<class TArchive>
    void serialize(TArchive& archive, const unsigned int /*version*/)
    {
        archive & boost::serialization::base_object<TPassChecker>(*this);
        archive & Name;
        archive & Listing;
    }

private:
    std::string Name;
    std::string Listing;
};
