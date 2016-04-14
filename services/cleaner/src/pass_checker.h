#pragma once

#include <string>

#include <boost/serialization/string.hpp>
#include <boost/serialization/access.hpp>

class TPassChecker {
public:
    TPassChecker(); 
    TPassChecker(std::string pass); 

    bool Check(std::string& pass) const;

private:
    friend class boost::serialization::access;
    template<class TArchive>
    void serialize(TArchive& archive, const unsigned int /*version*/) {
        archive & Pass;
    }

private:
    std::string Pass;
};
