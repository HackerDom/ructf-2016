#include "pass_checker.h"

TPassChecker::TPassChecker()
{
}

TPassChecker::TPassChecker(std::string pass)
    : Pass(pass)
{
}

void TPassChecker::SetPass(std::string& pass) {
    Pass = std::move(pass);
}

bool TPassChecker::Check(const std::string& pass) const {
    return Pass == pass;
}
