#include "parser.h"

TCommandParser::TCommandParser(const std::string& listing)
    : Listing(listing)
    , Idx(0)
    , State(EWaitCmd)
{
}

std::unique_ptr<ICommand> TCommandParser::GetNext() {
    char cmd;
    size_t num = 0;

    while (Idx < Listing.size()) {
        switch (State) {
            case EWaitCmd:
                cmd = Listing[Idx];
                State =  EWaitNumber1;
                break;
            case EWaitNumber1:
                if (!GetNum(num)) {
                    std::cout << "got error" << std::endl;
                    return std::unique_ptr<ICommand>(new TErrorCommand());
                }
                if (cmd == 'N') {
                    State = EWaitNumber2; 
                } else if (cmd == 'P') {
                    State = EWaitChar; 
                } else {
                    Idx++;
                    State = EWaitCmd; 
                    std::cout << "got move" << std::endl;
                    return std::unique_ptr<ICommand>(new TMoveCommand(cmd, num));
                }
                break;
            case EWaitNumber2:
                size_t num2;
                if (!GetNum(num2)) {
                    std::cout << "got error" << std::endl;
                    return std::unique_ptr<ICommand>(new TErrorCommand());
                }
                Idx++;
                State = EWaitCmd; 
                std::cout << "got new" << std::endl;
                return std::unique_ptr<ICommand>(new TNewCommand(num, num2));
            case EWaitChar:
                Idx++;
                State = EWaitCmd;
                std::cout << "got print" << std::endl;
                return std::unique_ptr<ICommand>(new TPrintCommand(Listing[Idx]));
            case EError:
                std::cout << "got error" << std::endl;
                Idx++;
                return std::unique_ptr<ICommand>(new TErrorCommand());
        };
        Idx++;
    };
    return nullptr;
}

bool TCommandParser::GetNum(size_t& num) {
    char buf = Listing[Idx]; 
    if (buf < '0' || buf > '9') {
        return false;
    }
    num = 10 * (buf - '0');
    Idx++;
    buf = Listing[Idx]; 
    if (buf < '0' || buf > '9') {
        return false;
    }
    num += (buf - '0');
    return true; 
}
