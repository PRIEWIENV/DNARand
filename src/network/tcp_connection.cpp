//
// Created by Blink on 2018/5/15.
//

#include "tcp_connection.hpp"

void TcpConnection::init() {
    peerAddr = socket_.remote_endpoint().address();
}

as::ip::tcp::socket& TcpConnection::socket() {
    return socket_;
}


bool TcpConnection::client_connect(as::ip::tcp::endpoint& endpoint) {
    boost::system::error_code error;
    socket_.connect(endpoint, error);
    if (!error) {
        std::cout << "connected to " << endpoint.address().to_string() << std::endl;
        return true;
    }
    return false;
}