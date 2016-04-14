#include "session.h"
#include "servant.h"

#include <boost/asio.hpp>
#include "boost/filesystem.hpp"

#include <cstdlib>
#include <iostream>
#include <thread>
#include <utility>

using boost::asio::ip::tcp;

const int PORT = 12500;

void session(tcp::socket sock) {
    try {
        TSession session(sock);
        TCleanerServant servant(session);
        servant.Dispatch();
    } catch (std::exception& e) {
        std::cerr << "Exception: " << e.what() << "\n";
    }
}

void server(boost::asio::io_service& io_service, unsigned short port) {
    tcp::acceptor acceptor(io_service, tcp::endpoint(tcp::v4(), port));
    while (true) {
        tcp::socket socket(io_service);
        acceptor.accept(socket);
        std::thread(session, std::move(socket)).detach();
    }
}

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
        server(io_service, PORT);
    } catch (std::exception& e) {
        std::cerr << "Exception: " << e.what() << "\n";
    }

    return 0;
}
