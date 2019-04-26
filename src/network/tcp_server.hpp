//
// Created by Blink on 2018/5/14.
//

#ifndef RAN_EXP_TCP_SERVER_HPP
#define RAN_EXP_TCP_SERVER_HPP
#include <ctime>
#include <iostream>
#include <string>
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <thread>
#include <future>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <map>
#include <sstream>
#include <vector>
#include "tcp_connection.hpp"
#include "client.hpp"

namespace as = boost::asio;

class TcpServer {
public:

    explicit TcpServer(as::io_service& io_service, int portNum)
            : acceptor_(io_service, as::ip::tcp::endpoint(as::ip::tcp::v4(), portNum)) {
        start_accept();
    }
    TcpServer() = delete;

private:
    void start_accept();
    void handle_accept(std::shared_ptr<Client> newClient,
                       const boost::system::error_code& error);
    as::ip::tcp::acceptor acceptor_;
};


#endif //RAN_EXP_TCP_SERVER_HPP
