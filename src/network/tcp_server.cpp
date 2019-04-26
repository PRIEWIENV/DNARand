//
// Created by Blink on 2018/5/14.
//

#include "tcp_server.hpp"

void TcpServer::start_accept() {
    std::shared_ptr<Client> newClient =
            Client::create(as::ip::address::from_string("0.0.0.0"), 0, false, acceptor_.get_io_service());
    std::cout << "[DEBUG] started accept socket" << std::endl;
    acceptor_.async_accept(newClient->socket(),
                           boost::bind(&TcpServer::handle_accept, this, newClient,
                                                                boost::asio::placeholders::error));
}

void TcpServer::handle_accept(std::shared_ptr<Client> newClient,
                              const boost::system::error_code &error) {
    if (!error) {
        std::cout << "[DEBUG] handling!!!!" << std::endl;
        std::cout << "New Connection from " +
                     newClient->socket().remote_endpoint().address().to_string() << std::endl;
        newClient->init_from_accept();
    } else {
        std::cout << boost::system::system_error(error).what() << std::endl;
    }

    start_accept();
}