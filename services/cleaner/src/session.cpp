#include "session.h"

bool TSession::ReadSocket(std::string& data) {
    boost::system::error_code error;
    size_t size = boost::asio::read_until(Socket, Response, "\n", error);

    if (!size || error == boost::asio::error::eof)
        return false;
    else if (error)
        throw boost::system::system_error(error);

    std::istream response_stream(&Response);
    std::getline(response_stream, data);

    return true;
}

bool TSession::WriteSocket(const std::string& data) {
    return boost::asio::write(Socket, boost::asio::buffer(data));
}
