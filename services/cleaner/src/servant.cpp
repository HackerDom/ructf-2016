#include "servant.h"

#include "saveloader.h"
#include "state.h"

#include <string>
#include <regex>

#include <boost/filesystem.hpp>
#include <boost/range/iterator_range.hpp>

const char* HELP = "\
=========================================================\n\
Hi, this is CLEANER - cleaner robot hivemind\n\
\n\
You can:\n\
1. upload your room plan and cleaner robot program\n\
   [upload - password - (room - plan | program - source))\n\
2. run program for your room\n\
   [run - password - room - program]\n\
3. get your room\n\
   [get_room - password - room]\n\
4. list existing rooms and programs\n\
   [list - (rooms | programs)]\n\
\n\
Pass each command or argument on a seperate line!\n\
=========================================================\n\
";

static const std::string ROOMS_DIR = "rooms";
static const std::string PROGRAMS_DIR = "programs";

bool LoadRoom(TRoom& room, const std::string& name) {
    boost::filesystem::path file(ROOMS_DIR + "/" + name);
    return NSaveloader::Load(room, file);
}

bool LoadProgram(TProgram& program, const std::string& name) {
    boost::filesystem::path file(PROGRAMS_DIR + "/" + name);
    return NSaveloader::Load(program, file);
}

bool RewriteRoom(TRoom& room) {
    boost::filesystem::path file(ROOMS_DIR + "/" + room.GetName());
    boost::filesystem::remove(file);
    return NSaveloader::Save(room, file);
}

bool SaveRoom(TRoom& room) {
    boost::filesystem::path file(ROOMS_DIR + "/" + room.GetName());
    return NSaveloader::Save(room, file);
}

bool SaveProgram(TProgram& program) {
    boost::filesystem::path file(PROGRAMS_DIR + "/" + program.GetName());
    return NSaveloader::Save(program, file);
}

bool ContainsNotAlphaNum(const std::string& str) {
    return !std::regex_match(str, std::regex("^[A-Za-z0-9]+$"));
}

TCleanerServant::TCleanerServant(TSession& session)
    : Session(session)
{
}

void TCleanerServant::Dispatch() {
    Session.Write(HELP);
    std::string action;
    Session.ReadLines(action);

    if (action == "upload") {
        Upload();
    } else if (action == "list") {
        List();
    } else if (action == "run") {
        Run();
    } else if (action == "get_room") {
        GetRoom();
    } else {
        Help();
    }
}

void TCleanerServant::Help() {
    Session.Write(HELP);
}

void TCleanerServant::Upload() {
    std::string pass;
    Session.ReadLines(pass);

    std::string entity;

    while (Session.ReadLinesImpl(entity)) {
        if (entity == "room") {
            std::string name;
            std::string plan;
            Session.ReadLines(name, plan);

            if (ContainsNotAlphaNum(name)) {
                Session.Write("Only alnum names allowed\n");
                return;
            }

            while (plan.size() % 8) {
                plan += " ";
            }

            TRoom room(name, pass, plan);
            if (!SaveRoom(room)) {
                Session.Write("Can't save room: already exists\n");
                return;
            }
        } else if (entity == "program") {
            std::string name;
            std::string source;
            Session.ReadLines(name, source);

            if (ContainsNotAlphaNum(name)) {
                Session.Write("Only alnum names allowed\n");
                return;
            }

            TProgram program(name, pass, source);
            if (!SaveProgram(program)) {
                Session.Write("Can't save program: already exists\n");
                return;
            }
        } else {
            Session.Write("Unknown entity : ", entity,  "\n");
            return;
        }
    }
}

void TCleanerServant::List() {
    std::string what;
    Session.ReadLines(what);

    if (what == "programs" || what == "rooms") {
        Session.Write("=========================================================\n");
        std::string result = ListDir(what);
        Session.Write(result); 
        Session.Write("=========================================================\n");
    } else {
        Session.Write("Unknown listing entity : ", what, "\n");
    }
}

std::string TCleanerServant::ListDir(const std::string& dir) const {
    using boost::filesystem::directory_iterator;
    using boost::filesystem::path;
    using boost::filesystem::is_regular_file;
    using boost::iterator_range;

    path target_dir(dir);
    auto range = iterator_range<directory_iterator>(directory_iterator(target_dir), directory_iterator());

    std::stringstream result;

    for (const auto& file : range) {
        if (is_regular_file(file)) {
           result << file.path().filename().string() << std::endl;
        }
    }

    return result.str();
}

void TCleanerServant::GetRoom() {
    std::string pass;
    std::string room_name;

    Session.ReadLines(pass, room_name);

    if (ContainsNotAlphaNum(room_name)) {
        Session.Write("Only alnum names allowed\n");
        return;
    }

    TRoom room;

    if (!LoadRoom(room, room_name)) {
        Session.Write("No such room\n");
        return;
    }

    if (!room.Check(pass)) {
        Session.Write("Bad creditionals\n");
        return;
    }

    const auto& plan = room.GetPlan();

    Session.Write(plan, "\n");
    Session.Write("Program results:\n");

    for (const auto& pair: room.GetLogs()) {
        TProgram program;
        if (!LoadProgram(program, pair.first)) {
            continue;
        }
        Session.Write(pair.first, "\n");
        Session.Write(program.GetSource(), "\n");
        Session.Write(pair.second, "\n");
    }
}

void TCleanerServant::Run() {
    std::string pass;
    std::string room_name;
    std::string program_name;

    Session.ReadLines(pass, room_name, program_name);

    TRoom room;
    TProgram program;
    TProgramState state;

    if (ContainsNotAlphaNum(room_name) || ContainsNotAlphaNum(program_name)) {
        Session.Write("Only alnum names allowed\n");
        return;
    }

    if (!LoadRoom(room, room_name) || !LoadProgram(program, program_name)) {
        Session.Write("Nonexistent entities\n");
        return;
    }

    if (!room.Check(pass) || !program.Check(pass)) {
        Session.Write("Bad creditionals\n");
        return;
    }

    program.Run(room, state);
    std::string log = state.Log.str();
    room.AddLog(program.GetName(), log);
    RewriteRoom(room);
    Session.Write(log, "\n");
}
