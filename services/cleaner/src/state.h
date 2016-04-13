#pragma once

struct TProgramState {
    size_t PosX = 0;
    size_t PosY = 0;
    size_t LogIdx = 0;
    std::string Log;

    void Append(char c) {
        Log[LogIdx++] = c;
    }
};
