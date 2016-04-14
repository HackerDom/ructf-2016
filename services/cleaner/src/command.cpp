#include "command.h"

TNewCommand::TNewCommand(size_t x, size_t y)
    : X(x)
    , Y(y)
{
}

bool Error(TProgramState& state) {
    state.Log << 'E';
    return false;
}

void PrintfNum(TProgramState& state, size_t num) {
    char buf[3];
    snprintf(buf, sizeof(buf), "%02lu", num);
    state.Log << buf;
}

bool TNewCommand::Run(TProgramState& state, TRoomConfiguration& configuration) const {
    std::cout << "run new " << X << " " << Y << " " << ((int) configuration[X * 8 + Y]) << std::endl;
    if (X * + Y < configuration.size() && configuration[X * 8 + Y] != 'W') {
        state.Log << 'N';
        PrintfNum(state, X);
        PrintfNum(state, Y);
        state.PosX = X;
        state.PosY = Y;
        return true;
    } else {
        return Error(state);
    }
}

TMoveCommand::TMoveCommand(char direction, size_t len) 
    : Direction(direction)
    , Len(len)
{
}

bool TMoveCommand::Run(TProgramState& state, TRoomConfiguration& configuration) const {
    bool error = false;
    size_t path_len = 0;

    for (size_t i = 0; i < Len; ++i) {
        size_t x = state.PosX;
        size_t y = state.PosY;
        std::cout << (ssize_t) x << " " << (ssize_t) y << " " << ((int) configuration[x * 8 + y]) << " " << configuration[x * 8 + y] <<std::endl;
        switch (Direction) {
            case 'L':
                if (x != 0 && configuration[(x - 1) * 8 + y] != 'W') {
                    state.PosX--;
                } else {
                    error = true;
                }
                break;
            case 'R':
                if (x + 1 < configuration.size() && configuration[(x + 1) * 8 + y] != 'W') {
                    state.PosX++;
                } else {
                    error = true;
                }
                break;
            case 'U':
                if (y < 7 && configuration[x * 8 + y + 1] != 'W') {
                    state.PosY++;
                } else {
                    error = true;
                }
                break;
            case 'D':
                if (y != 0 && configuration[x * 8 + (y - 1)] != 'W') {
                    state.PosY--;
                } else {
                    error = true;
                }
                break;
            default:
                error = true;
        }

        std::cout << "Run " << Direction << " "<< Len << " " << path_len << " " << error << std::endl;

        if (error) {
            break;
        } else {
            path_len++;
        }
    }

    if (path_len) {
        state.Log << Direction;
        PrintfNum(state, path_len);
    }

    size_t error_len = Len - path_len;

    if (error) {
        for (size_t i = 0; i < error_len; ++i) {
            state.Log << 'E';
        }
    }

    return !error;
}

bool TErrorCommand::Run(TProgramState& state, TRoomConfiguration& /*configuration*/) const {
    return Error(state);
}

TPrintCommand::TPrintCommand(char c)
    : Char(c)
{
}

bool TPrintCommand::Run(TProgramState& state, TRoomConfiguration& configuration) const {
    configuration[state.PosX * 8 + state.PosY] = Char;
    state.Log << 'P' << Char;
    return true;
}
