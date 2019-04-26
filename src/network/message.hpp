//
// Created by Blink on 2018/5/11.
//

#ifndef RAN_EXP_MESSAGE_HPP
#define RAN_EXP_MESSAGE_HPP

#include <ctime>
#include <iostream>
#include <string>
#include <boost/asio.hpp>
#include <boost/format.hpp>
#include <vector>
#include <map>
#include <list>
#include <boost/archive/text_iarchive.hpp>
#include <boost/archive/text_oarchive.hpp>
#include <boost/serialization/list.hpp>
#include "../crypto/crypto.hpp"

namespace as = boost::asio;

enum m_type {
    m_sync = 1,
    m_keepalive = 2,
    m_ack = 3,
    m_text = 4,
    m_share = 5,
    m_plainshare = 6,
    m_id = 7,
    m_edge = 8
};

class SerialzedMessage {
public:

    enum { HEADER_SIZE = 5 };
    enum { MAX_BODY_SIZE = 204800 };
    SerialzedMessage() {
        memset(data_, 0, HEADER_SIZE + MAX_BODY_SIZE);
    }

    const char* data() const {
        return data_;
    }

    char* data() {
        return data_;
    }
    size_t length() const {
        return HEADER_SIZE + MAX_BODY_SIZE;
    }

    const char* body() const {
        return data_ + HEADER_SIZE;
    }

    char* body() {
        return data_ + HEADER_SIZE;
    }

    size_t body_length() const {
        return body_size_;
    }

    void body_length(size_t new_length) {
        body_size_ = new_length;
        if (body_size_ > MAX_BODY_SIZE) {
            body_size_ = MAX_BODY_SIZE;
        }
    }

    m_type message_type() {
        return message_type_;
    }

    // TODO : decode type
    bool decode_header() {
        char header[HEADER_SIZE + 1] = "";
        memcpy(header, data_, HEADER_SIZE);
        body_size_ = *((int*)header);
        message_type_ = static_cast<m_type>(*((char*)header + 4));
        // TODO : exception
        if (body_size_ > MAX_BODY_SIZE) {
            body_size_ = 0;
            return false;
        }
        return true;
    }

    void encode_header(m_type type) {
        char header[HEADER_SIZE + 1] = "";
        memcpy(data_, header, HEADER_SIZE);
    }
private:
    char data_[HEADER_SIZE + MAX_BODY_SIZE];
    size_t body_size_;
    m_type message_type_;
};




class Message {
public:
    m_type type;
    int ttl;
    std::string from_ip;
    long time_stamp_global;
    Message(m_type _type, int _ttl, std::string _from_ip)
            : type(_type), ttl(_ttl), from_ip(_from_ip) {
        time_stamp_global = std::chrono::time_point_cast<std::chrono::milliseconds>(std::chrono::system_clock::now())
                .time_since_epoch().count();
    }
    Message() {}
    virtual ~Message() {}
private:
    friend class boost::serialization::access;
    template <class Archive>
    void serialize(Archive& ar, const unsigned int version) {
        ar & type;
        ar & ttl;
        ar & from_ip;
        ar & time_stamp_global;
    }

};

class IdMessage : public Message {
public:
    std::string id;
    IdMessage() {}
    IdMessage(m_type _type, int _ttl, std::string _from_ip, std::string _id)
            : Message(_type, _ttl, _from_ip), id(_id) {}

private:
    friend class boost::serialization::access;
    template <class Archive>
    void serialize(Archive& ar, const unsigned int version) {
        ar & boost::serialization::base_object<Message>(*this);
        ar & id;
    }
};

class EdgeMessage : public Message {
public:
    std::list<std::string> dsts;
    std::string src;
    EdgeMessage() {}
    EdgeMessage(m_type _type, int _ttl, std::string _from_ip, std::string _sender_id)
            : Message(_type, _ttl, _from_ip), src(_sender_id) {}

private:
    friend class boost::serialization::access;
    template <class Archive>
    void serialize(Archive& ar, const unsigned int version) {
        ar & boost::serialization::base_object<Message>(*this);
        ar & src;
        ar & dsts;
    }
};

class SyncMessage : public Message {
public:
    long time_stamp;
    std::string sender_id;
    bool ready;
    SyncMessage() {}
    SyncMessage(m_type _type, int _ttl, std::string _from_ip, std::string _sender_id, long _time_stamp, bool _ready)
            : Message(_type, _ttl, _from_ip), sender_id(_sender_id), time_stamp(_time_stamp), ready(_ready) {}
private:
    friend class boost::serialization::access;
    template <class Archive>
    void serialize(Archive& ar, const unsigned int version) {
        ar & boost::serialization::base_object<Message>(*this);
        ar & time_stamp;
        ar & sender_id;
        ar & ready;
    }
};

class TextMessage : public Message {
public:
    std::string msg;
    TextMessage() {}
    TextMessage(std::string _msg): msg(_msg) {}
    TextMessage(m_type _type, int _ttl, std::string _from_ip, std::string _msg)
            : Message(_type, _ttl, _from_ip), msg(_msg) {}

private:
    friend class boost::serialization::access;
    template <class Archive>
    void serialize(Archive& ar, const unsigned int version) {
        ar & boost::serialization::base_object<Message>(*this);
        ar & msg;
    }
};

class KeepaliveMessage : public Message {
public:
    enum keepalive_msg_type {
        m_echo = 0,
        m_reply = 1
    };
    keepalive_msg_type msg;
    KeepaliveMessage() {}
    KeepaliveMessage(m_type _type, int _ttl, std::string _from_ip, keepalive_msg_type _msg)
            : Message(_type, _ttl, _from_ip), msg(_msg) {}

private:
    friend class boost::serialization::access;
    template <class Archive>
    void serialize(Archive& ar, const unsigned int version) {
        ar & boost::serialization::base_object<Message>(*this);
        ar & msg;
    }
};

class Share {
public:
    Share() {}
    Share(std::string share_, ECDSA_SIG& sig_, std::string receiver_id_)
        : receiver_id(receiver_id_), encrypted_share(share_) {
        char *tmpSigR = BN_bn2hex(sig_.r);
        char *tmpSigS = BN_bn2hex(sig_.s);
        sigR = std::string(tmpSigR);
        sigS = std::string(tmpSigS);
        delete[] tmpSigR;
        delete[] tmpSigS;
    }
    std::string receiver_id;
    std::string encrypted_share;
    std::string sigR;
    std::string sigS;
private:
    friend class boost::serialization::access;
    template <class Archive>
    void serialize(Archive& ar, const unsigned int version) {
        ar & receiver_id;
        ar & encrypted_share;
        ar & sigR;
        ar & sigS;
    }
};

class SharesMessage : public Message {
public:
    SharesMessage() {}
    SharesMessage(m_type _type, int _ttl, std::string _from_ip, std::string sender_id_)
        : Message(_type, _ttl, _from_ip), sender_id(sender_id_) {}

    std::string sender_id; // id of sender
    std::list<Share> shares;
    /*
    std::string receiver_id; // id of receiver;
    std::string encrypted_share; // encrypted by receiver's ecdh key
    std::string sigR;
    std::string sigS;
     */
    //ECDSA_SIG sig; //
    //ECDSA_SIG sig; // sig for share, serialization not supported.
private:
    friend class boost::serialization::access;
    template <class Archive>
    void serialize(Archive& ar, const unsigned int version) {
        ar & boost::serialization::base_object<Message>(*this);
        ar & sender_id;
        ar & shares;
        //ar & sig;
    }
};

class AckMessage : public Message {
public:
    AckMessage() {}
    AckMessage(m_type _type, int _ttl, std::string _from_ip, std::string sender_id_)
        : Message(_type, _ttl, _from_ip), sender_id(sender_id_) {}

    std::string sender_id; // id of sender
private:
    friend class boost::serialization::access;
    template <class Archive>
    void serialize(Archive& ar, const unsigned int version) {
        ar & boost::serialization::base_object<Message>(*this);
        ar & sender_id;
    }
};

class PlainShareM {
public:
    PlainShareM() {}
    PlainShareM(std::string share_, ECDSA_SIG& sig_, std::string sender_id_)
        : sender_id(sender_id_), share(share_) {
        char *tmpSigR = BN_bn2hex(sig_.r);
        char *tmpSigS = BN_bn2hex(sig_.s);
        sigR = std::string(tmpSigR);
        sigS = std::string(tmpSigS);
        delete[] tmpSigR;
        delete[] tmpSigS;
    }
    PlainShareM(std::string share_, std::string sigR_, std::string sigS_, std::string sender_id_)
        : sender_id(sender_id_), share(share_), sigR(sigR_), sigS(sigS_) {}

    std::string sender_id;
    std::string share;
    std::string sigR;
    std::string sigS;
private:
    friend class boost::serialization::access;
    template <class Archive>
    void serialize(Archive& ar, const unsigned int version) {
        ar & sender_id;
        ar & share;
        ar & sigR;
        ar & sigS;
    }
};


class PlainSharesMessage : public Message {
public:
    PlainSharesMessage() {}
    PlainSharesMessage(m_type _type, int _ttl, std::string _from_ip) : Message(_type, _ttl, _from_ip) {}
    std::list<PlainShareM> plainshares;

private:
    friend class boost::serialization::access;
    template <class Archive>
    void serialize(Archive& ar, const unsigned int version) {
        ar & boost::serialization::base_object<Message>(*this);
        ar & plainshares;
    }
};

#endif //RAN_EXP_MESSAGE_HPP
