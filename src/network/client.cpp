//
// Created by Blink on 2018/5/10.
//

#include "client.hpp"
#include <sstream>
#include <boost/system/system_error.hpp>

extern  MsgQueue<std::shared_ptr<Message> > manager::recvMsgQ;

void Client::init_from_accept() {
    ip = socket_.remote_endpoint().address();
    port = socket_.remote_endpoint().port();
    std::shared_ptr<Client> tmp = ptr();
    Peers::getInstance()->addNeighboor(tmp);
    //std::cout << "[DEBUG] pre-start handle read" << std::endl;
    start_handle_message();
    //std::cout << "[DEBUG] post-start handle read" << std::endl;
    auto writeThread = std::thread(&Client::handle_write, shared_from_this());
    writeThread.detach();
    IdMessage im(m_id, 0, std::string("0.0.0.0"), manager::getMyId());
    send(std::make_shared<IdMessage>(im));
    //std::cout << "[DEBUG] pre-start handle write" << std::endl;
    //handle_write(boost::system::errc::make_error_code(boost::system::errc::success));
    //std::cout << "[DEBUG] post-start handle write" << std::endl;
}

as::ip::tcp::socket& Client::socket() {
    return socket_;
}
bool Client::connect() {
    as::ip::tcp::endpoint endpoint(ip, port);
    boost::system::error_code error;
    socket_.connect(endpoint, error);
    if (!error) {
        //std::cout << "connected to " << endpoint.address().to_string() << std::endl;
        //auto readThread = std::thread(&Client::start_handle_message, shared_from_this());
        start_handle_message();
        auto writeThread = std::thread(&Client::handle_write, shared_from_this());
        writeThread.detach();
        IdMessage im(m_id, 0, std::string("0.0.0.0"), manager::getMyId());
        send(std::make_shared<IdMessage>(im));
        //readThread.detach();
        //handle_write(boost::system::errc::make_error_code(boost::system::errc::success));
        return true;
    }
    socket_ = as::ip::tcp::socket(Peers::getInstance()->get_io_service());
    //new boost::asio::ip::tcp::socket(io_service)
    return false;
}

Client::Client(as::ip::address _ip, int _port, bool _connectTo, as::io_service& io_service): ip(_ip), port(_port), connectTo(_connectTo), socket_(io_service) {}


void Client::start_handle_message() {
    //as::async_read(conn->socket(), )
    //std::cout << "[DEBUG] started handle read header" << std::endl;
    as::async_read(socket_, as::buffer(read_msg.data(), SerialzedMessage::HEADER_SIZE),
                   boost::bind(&Client::handle_header, shared_from_this(), as::placeholders::error));
}

void Client::handle_header(const boost::system::error_code &error) {
   //std::cout << "[DEBUG] started handle read body" << std::endl;
    if (!error && read_msg.decode_header()) {
        //std::cout << "[DEBUG] decoded header: body_size: " << read_msg.body_length() << std::endl;
        //std::cout << "[DEBUG] decoded header: msg_type: " << read_msg.message_type() << std::endl;
        as::async_read(socket_, as::buffer(read_msg.body(), read_msg.body_length()),
                       boost::bind(&Client::handle_body, shared_from_this(), as::placeholders::error));
    } else {
        std::cout << boost::system::system_error(error).what() << std::endl;
    }
}

void Client::handle_body(const boost::system::error_code &error) {
    //std::cout << "[DEBUG] started handle body" << std::endl;
    read_msg.body()[read_msg.body_length()] = 0;
    std::istringstream istream(read_msg.body());
    std::string tmp = std::string(read_msg.body(), read_msg.body_length());
    bool found = Peers::getInstance()->delivered_msg.lookup(tmp);
    //std::cout << "[DEBUG DELIVER] string msg: " << tmp << " found: " << found << std::endl;
    //TODO: hash
    if (found) {
        start_handle_message();
        return ;
    }
    std::shared_ptr<Message> MsgToDeliver;

    boost::archive::text_iarchive ia(istream);
    switch(read_msg.message_type()) {
        case m_keepalive: {
            KeepaliveMessage kM;
            ia >> kM;
            MsgToDeliver = std::make_shared<KeepaliveMessage>(kM);
            break;
        }
        case m_text: {
            TextMessage tM;
            ia >> tM;
            MsgToDeliver = std::make_shared<TextMessage>(tM);
            std::cout << tM.msg << std::endl;
            break;
        }
        case m_share: {
            SharesMessage sM;
            ia >> sM;
            MsgToDeliver = std::make_shared<SharesMessage>(sM);
            break;
        }
        case m_ack: {
            AckMessage aM;
            ia >> aM;
            MsgToDeliver = std::make_shared<AckMessage>(aM);
            break;
        }
        case m_plainshare: {
            PlainSharesMessage pM;
            ia >> pM;
            MsgToDeliver = std::make_shared<PlainSharesMessage>(pM);
            break;
        }
        case m_sync: {
            SyncMessage sM;
            ia >> sM;
            MsgToDeliver = std::make_shared<SyncMessage>(sM);
            break;
        }
        case m_id: {
            IdMessage iM;
            ia >> iM;
            std::shared_ptr<Client> tmp = ptr();
            Peers::getInstance()->addNeighboor(iM.id, tmp);
            start_handle_message();
            return ;
        }
        case m_edge: {
            EdgeMessage eM;
            ia >> eM;
            MsgToDeliver = std::make_shared<EdgeMessage>(eM);
            break;
        }
    }
    if (Peers::getInstance()->getBcastMode() == m_FLOOD) {
        for (auto&& client : Peers::getInstance()->allNeighboors()) {
            if ((*client) == (*shared_from_this())) {
                continue;
            }
            client->send(MsgToDeliver);
        }
    } else {
        std::string fromId = MsgToDeliver->from_ip;
        auto bcastLists = Peers::getInstance()->getBcastList();
        auto range = bcastLists.equal_range(fromId);
        for (auto i = range.first; i != range.second; i ++) {
            i->second->send(MsgToDeliver);
        }
    }
    //std::cout << "[DEBUG DELIVER] Delivered message" << std::endl;
    manager::recvMsgQ.push(MsgToDeliver);
    start_handle_message();
}

void Client::send(std::shared_ptr<Message> msg) {
    write_queue.push(msg);
}

void Client::handle_socket_error(boost::system::error_code &error) {
    std::cout << boost::system::system_error(error).what() << std::endl;
    return ;
}

bool Client::isConnectTo() {
    return connectTo;
}

void Client::handle_write() {
    //write_buffers.clear();
    std::shared_ptr<Message> msg;
    std::shared_ptr<KeepaliveMessage> km;
    std::shared_ptr<TextMessage> tm;
    std::shared_ptr<SharesMessage> sm;
    std::shared_ptr<AckMessage> am;
    std::shared_ptr<PlainSharesMessage> pm;
    std::shared_ptr<SyncMessage> syncm;
    std::shared_ptr<IdMessage> idm;
    std::shared_ptr<EdgeMessage> em;
    while (socket_.is_open()) {
        write_queue.pop(msg);
        std::ostringstream archive_stream;
        boost::archive::text_oarchive archive(archive_stream);
        //std::cout << "[DEBUG] poped Message " << std::endl;
        switch (msg->type) {
            case m_keepalive: {
                km = std::dynamic_pointer_cast<KeepaliveMessage>(msg);
                archive << (*km);
                break;
            }
            case m_text: {
                tm = std::dynamic_pointer_cast<TextMessage>(msg);
                //std::cout << "[DEBUG] before Archive TextMessage" << tm->msg << std::endl;
                archive << (*tm);
                //std::cout << "[DEBUG] write TextMessage " << tm->msg << std::endl;
                break;
            }
            case m_share: {
                sm = std::dynamic_pointer_cast<SharesMessage>(msg);
                //std::cout << "[DEBUG] before Archive SharesMessage" << std::endl;
                archive << (*sm);
                //std::cout << "[DEBUG] write SharesMessage " << std::endl;
                break;
            }
            case m_ack: {
                am = std::dynamic_pointer_cast<AckMessage>(msg);
                //std::cout << "[DEBUG] before Archive AckMessage" << std::endl;
                archive << (*am);
                //std::cout << "[DEBUG] write AckMessage" << std::endl;
                break;
            }
            case m_plainshare: {
                pm = std::dynamic_pointer_cast<PlainSharesMessage>(msg);
                //std::cout << "[DEBUG] before Archive PlainSharesMessage" << std::endl;
                archive << (*pm);
                //std::cout << "[DEBUG] write PlainSharesMessage" << std::endl;
                break;
            }
            case m_sync: {
                syncm = std::dynamic_pointer_cast<SyncMessage>(msg);
                //std::cout << "[DEBUG] before Archive SyncMessage" << std::endl;
                archive << (*syncm);
                //std::cout << "[DEBUG] write SyncMessage" << std::endl;
                break;
            }
            case m_id: {
                idm = std::dynamic_pointer_cast<IdMessage>(msg);
                archive << (*idm);
                break;
            }
            case m_edge: {
                em = std::dynamic_pointer_cast<EdgeMessage>(msg);
                archive << (*em);
                break;
            }
        }
        boost::system::error_code ec;
        std::string write_serialized_msg = archive_stream.str();
        size_t body_size = write_serialized_msg.length();
        Peers::getInstance()->delivered_msg.lookup(write_serialized_msg);
        char msg_type = (char)msg->type;
        /*
        socket_.write_some(as::buffer(&(body_size), 4));
        socket_.write_some(as::buffer(&(msg_type), 1));
        socket_.write_some(as::buffer(archive_stream.str()));
        */
        write_buffers.clear();
        write_buffers.push_back(as::buffer(&(body_size), 4));
        write_buffers.push_back(as::buffer(&(msg_type), 1));
        write_buffers.push_back(as::buffer(write_serialized_msg, body_size));
        //as::async_write(socket_, write_buffers,
        //                boost::bind(&Client::handle_write, shared_from_this(),
        //                            boost::asio::placeholders::error));

        as::write(socket_, write_buffers);
    }
}

/*

EC_KEY* Client::getPubKey() {
    return pubKey;
}

unsigned char* Client::getEcdhKey() {
    return ecdhKey;
}

int Client::getEcdhKeyLen() {
    return ecdhKeyLen;
}

bool Client::setEcdhKey(unsigned char *key, int len) {
    ecdhKey = key;
    ecdhKeyLen = len;
}

 */