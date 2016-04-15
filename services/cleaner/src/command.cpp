#include "command.h"

bool Error(TProgramState& state) {
    state.Log << 'E';
    return false;
}

void PrintfNum(TProgramState& state, size_t num) {
    char buf[3];
    snprintf(buf, sizeof(buf), "%02lu", num);
    state.Log << buf;
}

TNewCommand::TNewCommand(size_t x, size_t y)
    : X(x)
    , Y(y)
{
}

bool TNewCommand::Run(TProgramState& state, TRoomPlan& plan) const {
    if (X * + Y < plan.size() && plan[X * 8 + Y] != 'W') {
        state.Log << 'N';
        PrintfNum(state, X);
        PrintfNum(state, Y);
        state.PosX = X;
        state.PosY = Y;
        return true;
    } 

    return Error(state);
}

TMoveCommand::TMoveCommand(char direction, size_t len)
    : Direction(direction)
    , Len(len)
{
}

bool TMoveCommand::Run(TProgramState& state, TRoomPlan& plan) const {
    bool error = false;
    size_t path_len = 0;

    for (size_t i = 0; i < Len; ++i) {
        size_t x = state.PosX;
        size_t y = state.PosY;
        switch (Direction) {
            case 'L':
                if (x != 0 && plan[(x - 1) * 8 + y] != 'W') {
                    state.PosX--;
                } else {
                    error = true;
                }
                break;
            case 'R':
                if (x + 1 < plan.size() && plan[(x + 1) * 8 + y] != 'W') {
                    state.PosX++;
                } else {
                    error = true;
                }
                break;
            case 'U':
                if (y < 7 && plan[x * 8 + y + 1] != 'W') {
                    state.PosY++;
                } else {
                    error = true;
                }
                break;
            case 'D':
                if (y != 0 && plan[x * 8 + (y - 1)] != 'W') {
                    state.PosY--;
                } else {
                    error = true;
                }
                break;
            default:
                error = true;
        }

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

bool TErrorCommand::Run(TProgramState& state, TRoomPlan& /*plan*/) const {
    return Error(state);
}

TPrintCommand::TPrintCommand(char c)
    : Char(c)
{
}

bool TPrintCommand::Run(TProgramState& state, TRoomPlan& plan) const {
    plan[state.PosX * 8 + state.PosY] = Char;
    state.Log << 'P' << Char;
    return true;
}
