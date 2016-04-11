#include "servant.h"

#include "saveloader.h"

#include <string>

#include <boost/filesystem.hpp>
#include <boost/range/iterator_range.hpp>
#include <boost/algorithm/hex.hpp>

const char* HELLO = "\
SOME\n\
NICE\n\
ASCII\n\
ART\n\
==============\n\
";

const char* HELP = "\
THIS\n\
IS\n\
HELP\n\
";

static const std::string ROOMS_DIR = "rooms";
static const std::string PROGRAMS_DIR = "programs";

// TODO: write check
bool LoadRoom(TRoom& room, const std::string& name) {
    boost::filesystem::path file(ROOMS_DIR + "/" + name);
    return NSaveloader::Load(room, file);
}

bool LoadProgram(TProgram& program, const std::string& name) {
    boost::filesystem::path file(PROGRAMS_DIR + "/" + name);
    return NSaveloader::Load(program, file);
}

bool SaveRoom(TRoom& room) {
    boost::filesystem::path file(ROOMS_DIR + "/" + room.GetName());
    return NSaveloader::Save(room, file);
}

bool SaveProgram(TProgram& program) {
    boost::filesystem::path file(PROGRAMS_DIR + "/" + program.GetName());
    return NSaveloader::Save(program, file);
}

TCleanerServant::TCleanerServant(TSession& session)
    : Session(session)
{
}

void TCleanerServant::Dispatch() {
    Session.Write(HELLO);
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
    } else if (action == "change_pass") {
        ChangeRoomPass();
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

    while (Session.ReadLines(entity)) {
        if (entity == "room") {
            std::string name;
            std::string configuration_hex;
            Session.ReadLines(name, configuration_hex);
            TRoomConfiguration configuration;
            boost::algorithm::unhex(configuration_hex.begin(), configuration_hex.end(), std::back_inserter(configuration));
            TRoom room(name, pass, configuration);
            if (!SaveRoom(room)) {
                Session.Write("Can't save room: already exists\n");
            }
        } else if (entity == "program") {
            std::string name;
            std::string listing;
            Session.ReadLines(name, listing);
            TProgram program(name, listing, pass);
            if (!SaveProgram(program)) {
                Session.Write("Can't save program: already exists\n");
            }
        } else {
            Session.Write("Unknown entity : ", entity,  "\n");
        }
    }
}

void TCleanerServant::List() {
    std::string what;
    Session.ReadLines(what);

    if (what == "programs" || what == "rooms") {
        Session.Write(ListDir(what)); 
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

    TRoom room;

    if (!LoadRoom(room, room_name)) {
        Session.Write("No such room\n");
        return;
    }

    if (!room.Check(pass)) {
        Session.Write("Bad creditionals\n");
        return;
    }

    const auto& configuration = room.GetConfiguration();
    std::string configuration_hex;
    boost::algorithm::hex(configuration.begin(), configuration.end(), std::back_inserter(configuration_hex));
    Session.Write(configuration_hex, "\n");
}

void TCleanerServant::ChangeRoomPass() {
    std::string pass;
    std::string room_name;

    Session.ReadLines(pass, room_name);

    TRoom room;

    if (!LoadRoom(room, room_name)) {
        Session.Write("No such room\n");
        return;
    }

    Session.Write("Tell me about your hall\n");

    std::string hall;
    Session.ReadLines(hall);

    if (!room.CheckHall(hall)) {
        Session.Write("Wrong!\n");
        return;
    }

    room.SetPass(pass);
    boost::filesystem::path room_path(ROOMS_DIR + "/" + room_name);
    boost::filesystem::remove(room_path);
    SaveRoom(room);

    Session.Write("Ok\n");
}

void TCleanerServant::Run() {
    std::string pass;
    std::string room_name;
    std::string program_name;

    Session.ReadLines(pass, room_name, program_name);

    TRoom room;
    TProgram program;

    if (!LoadRoom(room, room_name) || !LoadProgram(program, program_name)) {
        Session.Write("Nonexistent entities\n");
        return;
    }

    if (!room.Check(pass) || !program.Check(pass)) {
        Session.Write("Bad creditionals\n");
        return;
    }

    Session.Write(program.Run(room), "\n");
}
