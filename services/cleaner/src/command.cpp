#include "command.h"

TNewCommand::TNewCommand(size_t x, size_t y)
    : X(x)
    , Y(y)
{
}

bool Allow(size_t x, size_t y, const TRoomConfiguration& configuration) {
    return configuration.size() < x && y < 8 * sizeof(unsigned long) && !(configuration[x] & (1 << y));
}

bool Error(TProgramState& state) {
    state.Append('E');
    return false;
}

bool TNewCommand::Run(TProgramState& state, const TRoomConfiguration& configuration) const {
    if (Allow(X, Y, configuration)) {
        state.Append('N');
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
        switch (Direction) {
            case 'L':
                if (i > state.PosX || !Allow(state.PosX - i, state.PosY, configuration)) {
                    error = true;
                }
                break;
            case 'R':
                if (i + state.PosX > configuration.size() || !Allow(state.PosX + i, state.PosY, configuration)) {
                    error = true;
                }
                break;
            case 'U':
                if (state.PosY + i > 8 * sizeof(unsigned long) || !Allow(state.PosX, state.PosY + i, configuration)) {
                    error = true;
                }
                break;
            case 'D':
                if (i > state.PosY || !Allow(state.PosX, state.PosY - i, configuration)) {
                    error = true;
                }
                break;
            default:
                error = true;
        }

        if (error) {
            state.Append('E');
        } else {
            path_len++;
        }
    }

    if (path_len) {
        state.Append(Direction);
        std::string path_str = std::to_string(path_len);
        for (char c: path_str) {
            state.Append(c);
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
