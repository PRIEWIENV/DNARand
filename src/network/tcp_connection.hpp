//
// Created by Blink on 2018/5/15.
//

#ifndef RAN_EXP_TCP_CONNECTION_HPP
#define RAN_EXP_TCP_CONNECTION_HPP
#include <ctime>
#include <iostream>
#include <string>
#include <boost/asio.hpp>
#include <thread>
#include <future>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <map>
#include <sstream>
#include <vector>
#include "msg_queue.hpp"

namespace as = boost::asio;

class TcpConnection
        : public std::enable_shared_from_this<TcpConnection> {
public:
    typedef std::shared_ptr<TcpConnection> conPointer;

    void init();

    bool client_connect(as::ip::tcp::endpoint& endpoint);

    static conPointer create(as::io_service& io_service) {
        conPointer tmp = conPointer(new TcpConnection(io_service));
        return tmp;
    }

    as::ip::tcp::socket& socket();

private:
    TcpConnection(as::io_service& io_service)
            : socket_(io_service) {}

    as::ip::tcp::socket socket_;
    as::ip::address peerAddr;
};


#endif //RAN_EXP_TCP_CONNECTION_HPP
