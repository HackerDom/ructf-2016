#include "server.h"

#include "session.h"
#include "servant.h"

#include <cstdlib>
#include <iostream>
#include <boost/bind.hpp>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

using boost::asio::ip::tcp;

TServer::TServer(boost::asio::io_service& io_service, unsigned short port)
    : IoService(io_service)
    , Signal(io_service, SIGCHLD)
    , Acceptor(io_service, tcp::endpoint(tcp::v4(), port))
    , Socket(io_service)
{
    StartSignalWait();
    StartAccept();
}

void TServer::StartSignalWait() {
    Signal.async_wait(boost::bind(&TServer::HandleSignalWait, this));
}

void TServer::HandleSignalWait() {
    if (Acceptor.is_open()) {
        int status = 0;
        while (waitpid(-1, &status, WNOHANG) > 0) {
        }

        StartSignalWait();
    }
}

void TServer::StartAccept() {
    Acceptor.async_accept(Socket, boost::bind(&TServer::HandleAccept, this, _1));
}

void TServer::HandleAccept(const boost::system::error_code& ec) {
    if (!ec) {
        IoService.notify_fork(boost::asio::io_service::fork_prepare);

        if (fork() == 0) {
            IoService.notify_fork(boost::asio::io_service::fork_child);
            Acceptor.close();
            Signal.cancel();

            try {
                TSession session(Socket);
                TCleanerServant servant(session);
                servant.Dispatch();
            } catch (std::exception& e) {
                std::cerr << "Exception: " << e.what() << "\n";
            }
        } else {
            IoService.notify_fork(boost::asio::io_service::fork_parent);
            Socket.close();
            StartAccept();
        }
    }
    else {
        std::cerr << "Accept error: " << ec.message() << std::endl;
        StartAccept();
    }
}
