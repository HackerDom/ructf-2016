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
    state.Log += "E";
    return false;
}

bool TNewCommand::Run(TProgramState& state, const TRoomConfiguration& configuration) const {
    if (Allow(X, Y, configuration)) {
        state.Log += "N";
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
            break;
        }
        path_len++;
    }
    if (path_len) {
        state.Log += std::to_string(Direction);
        state.Log += std::to_string(path_len);
    }
    if (error) {
        return Error(state);
    }
    return true;
}

bool TErrorCommand::Run(TProgramState& state, const TRoomConfiguration& /*configuration*/) const {
    return Error(state);
}
