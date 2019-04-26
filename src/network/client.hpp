//
// Created by Blink on 2018/5/10.
//

#ifndef RAN_EXP_CLIENT_H
#define RAN_EXP_CLIENT_H

#include <ctime>
#include <iostream>
#include <string>
#include <boost/asio.hpp>
#include <vector>
#include <map>
#include <mutex>
#include <condition_variable>
#include "tcp_connection.hpp"
#include "peers.hpp"
#include "msg_queue.hpp"
#include "message.hpp"
#include "../tools/manager.hpp"
#include <boost/bind.hpp>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>

namespace as = boost::asio;

class Client : public std::enable_shared_from_this<Client> {
public:
    Client() = delete;
    //client &operator= (const client&) = delete;

    static std::shared_ptr<Client> create(as::ip::address _ip, int _port, bool _connectTo, as::io_service& io_service) {
        std::shared_ptr<Client> tmp = std::shared_ptr<Client> (new Client(_ip, _port, _connectTo, io_service));
        return tmp;
    }

    std::shared_ptr<Client> ptr() {
        return shared_from_this();
    }

    as::ip::address getIP() const {
        return ip;
    }

    int getPort() const {
        return port;
    }
    bool operator == (const Client& other) const {
        return other.getIP() == ip && other.getPort() == port;
    }

    void init_from_accept();

    void start_handle_message();

    void handle_header(const boost::system::error_code &error);

    void handle_body(const boost::system::error_code &error);

    bool connect();

    // send message (async)
    void send(std::shared_ptr<Message> msg);

    void handle_socket_error(boost::system::error_code &error);

    //void handle_write(const boost::system::error_code &error);
    void handle_write();

    bool isConnectTo();

    //EC_KEY* getPubKey();

    //unsigned char* getEcdhKey();

    //int getEcdhKeyLen();

    as::ip::tcp::socket& socket();

    bool setEcdhKey(unsigned char* key, int len);

private:
    Client(as::ip::address _ip, int _port, bool _connectTo, as::io_service& io_service);
    as::ip::address ip;
    int port;
    //TcpConnection::conPointer conn;
    as::ip::tcp::socket socket_;
    std::mutex mutex_conn;
    bool alive; // 存活
    bool connectTo; // 主动连接
    MsgQueue<std::shared_ptr<Message> > write_queue;
    SerialzedMessage read_msg;
    std::vector<as::const_buffer> write_buffers;
    LRUSet<std::string> delivered_msg;
    // TODO: Public Key and others
    //EC_KEY *pubKey;
    //unsigned char *ecdhKey;
    //int ecdhKeyLen;
};


#endif //RAN_EXP_CLIENT_H
