#include "session.h"
#include "servant.h"

#include <boost/asio.hpp>

#include <cstdlib>
#include <iostream>
#include <thread>
#include <utility>

using boost::asio::ip::tcp;

void session(tcp::socket sock) {
    try {
        TSession session(sock);
        TCleanerServant servant(session);
        servant.Dispatch();
    } catch (...) {
    }
}

void server(boost::asio::io_service& io_service, unsigned short port) {
    tcp::acceptor acceptor(io_service, tcp::endpoint(tcp::v4(), port));
    for (;;)
    {
        tcp::socket socket(io_service);
        acceptor.accept(socket);
        std::thread(session, std::move(socket)).detach();
    }
}

int main(int argc, char* argv[]) {
    try {
        if (argc != 2) {
            std::cerr << "Usage: cleaner <port>\n";
            return 1;
        }

        boost::asio::io_service io_service;
        server(io_service, std::atoi(argv[1]));
    } catch (std::exception& e) {
        std::cerr << "Exception: " << e.what() << "\n";
    }

    return 0;
}
