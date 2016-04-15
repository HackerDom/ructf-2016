#include "server.h"

#include "boost/filesystem.hpp"
#include <boost/asio/io_service.hpp>

#include <iostream>

const int PORT = 12500;

int main(int argc, char* argv[]) {
    boost::filesystem::path programs ( "./programs" );
    boost::filesystem::path rooms ( "./rooms" );

    if (!exists(programs)) {
        boost::filesystem::create_directory(programs);
    }

    if (!exists(rooms)) {
        boost::filesystem::create_directory(rooms);
    }

    try {
        boost::asio::io_service io_service;
        TServer s(io_service, PORT);
        io_service.run();
    } catch (std::exception& e) {
        std::cerr << "Exception: " << e.what() << "\n";
    }

    return 0;
}
