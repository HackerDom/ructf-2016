#pragma once

#include "session.h"
#include "room.h"
#include "program.h"

#include <istream>
#include <ostream>
#include <sstream>

class TCleanerServant {
public:
    TCleanerServant(TSession& session);
    void Dispatch();

private:
    void Help();

    void Upload();

    void List();
    std::string ListDir(const std::string& dir) const;

    void GetRoom();

    void Run();

private:
    TSession& Session;
};
