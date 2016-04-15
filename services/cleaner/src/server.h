#pragma once

#include <boost/asio/io_service.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/signal_set.hpp>

class TServer {
public:
    TServer(boost::asio::io_service& io_service, unsigned short port);

private:
    void StartSignalWait();
    void HandleSignalWait();
    void StartAccept();
    void HandleAccept(const boost::system::error_code& ec);

private:
    boost::asio::io_service& IoService;
    boost::asio::signal_set Signal;
    boost::asio::ip::tcp::acceptor Acceptor;
    boost::asio::ip::tcp::socket Socket;
};
