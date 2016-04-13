#include "command.h"

TNewCommand::TNewCommand(size_t x, size_t y)
    : X(x)
    , Y(y)
{
}

bool Error(TProgramState& state) {
    state.Append('E');
    return false;
}

void PrintfNum(TProgramState& state, size_t num) {
    char buf[3];
    snprintf(buf, sizeof(buf), "%02lu", num);
    state.Append(buf[0]);
    state.Append(buf[1]);
}

bool TNewCommand::Run(TProgramState& state, const TRoomConfiguration& configuration) const {
    std::cout << "run new " << X << " " << Y << " " << ((int) configuration[X]) << std::endl;
    if (X < configuration.size() && Y < 8 && !(configuration[X] & (1 << Y))) {
        state.Append('N');
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

bool TMoveCommand::Run(TProgramState& state, const TRoomConfiguration& configuration) const {
    bool error = false;
    size_t path_len = 0;

    for (size_t i = 0; i < Len; ++i) {
        size_t x = state.PosX;
        size_t y = state.PosY;
        std::cout << x << " " << y << " " << ((int) configuration[x]) << std::endl;
        switch (Direction) {
            case 'L':
                if (x != 0 && !(configuration[x - 1] & (1 << y))) {
                    state.PosX--;
                } else {
                    error = true;
                }
                break;
            case 'R':
                if (x < configuration.size() && !(configuration[x + 1] & (1 << y))) {
                    state.PosX++;
                } else {
                    error = true;
                }
                break;
            case 'U':
                if (y < 8 && !(configuration[x] & (1 << (y + 1)))) {
                    state.PosY++;
                } else {
                    error = true;
                }
                break;
            case 'D':
                if (y != 0 && !(configuration[x] & (1 << (y - 1)))) {
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
        state.Append(Direction);
        PrintfNum(state, path_len);
    }

    size_t error_len = Len - path_len;

    if (error) {
        for (size_t i = 0; i < error_len; ++i) {
            state.Append('E');
        }
    }

    return !error;
}

bool TErrorCommand::Run(TProgramState& state, const TRoomConfiguration& /*configuration*/) const {
    return Error(state);
}

TPrintCommand::TPrintCommand(char c)
    : Char(c)
{
}

bool TPrintCommand::Run(TProgramState& state, const TRoomConfiguration& /*configuration*/) const {
    state.Append(Char);
    return true;
}
