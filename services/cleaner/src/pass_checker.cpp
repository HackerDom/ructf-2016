#include "pass_checker.h"

#include <openssl/md5.h>
#include <sstream>

#include <boost/algorithm/hex.hpp>

class TMD5Calcer {
public:
    TMD5Calcer() {
        MD5_Init(&Context);
    }

    void Upadate(std::string& str) {
        std::string buf(std::move(str));
        MD5_Update(&Context, buf.c_str(), buf.size());
    }

    std::string Final() {
        unsigned char hash[MD5_DIGEST_LENGTH];
        MD5_Final((unsigned char *)hash, &Context);

        std::string result;
        boost::algorithm::hex(hash, hash + MD5_DIGEST_LENGTH, std::back_inserter(result));

        return result;
    }

private:
    MD5_CTX Context;
};

TPassChecker::TPassChecker()
{
}

TPassChecker::TPassChecker(std::string pass)
{
    TMD5Calcer md5;
    md5.Upadate(pass);
    Pass = md5.Final();
}

bool TPassChecker::Check(std::string& pass) const {
    TMD5Calcer md5;
    md5.Upadate(pass);
    std::string hashed_pass = md5.Final();
    return Pass == hashed_pass;
}
