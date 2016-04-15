#pragma once

#include "room.h"
#include "state.h"

class ICommand {
public:
    virtual bool Run(TProgramState& state, TRoomConfiguration& configuration) const = 0;
};

class TNewCommand : public ICommand {
public:
    TNewCommand(size_t x, size_t y);
    virtual bool Run(TProgramState& state, TRoomConfiguration& configuration) const;
private:
    const size_t X;
    const size_t Y;
};

class TMoveCommand : public ICommand {
public:
    TMoveCommand(char direction, size_t len);
    virtual bool Run(TProgramState& state, TRoomConfiguration& configuration) const;
private:
    const char Direction;
    const size_t Len;
};

class TPrintCommand : public ICommand {
public:
    TPrintCommand(char c);
    virtual bool Run(TProgramState& state, TRoomConfiguration& configuration) const;
private:
    const char Char;
};

class TErrorCommand : public ICommand {
    virtual bool Run(TProgramState& state, TRoomConfiguration& configuration) const;
};
