#pragma once

#include <sstream>

struct TProgramState {
    size_t PosX = -1;
    size_t PosY = -1;
    std::stringstream Log;
};
