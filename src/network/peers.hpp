//
// Created by Blink on 2018/5/10.
//

#ifndef RAN_EXP_PEERS_H
#define RAN_EXP_PEERS_H

#include <ctime>
#include <iostream>
#include <string>
#include <boost/asio.hpp>
#include <boost/format.hpp>
#include <vector>
#include <map>
#include "client.hpp"
#include "msg_queue.hpp"
#include <list>

namespace as = boost::asio;

class Client;

enum m_bcast_mode {
    m_FLOOD = 1,
    m_SPT = 2
};

// TODO : thread safe
class Peers {
public:
    Peers(Peers const&) = delete;
    void operator = (Peers const&) = delete;
    static Peers* getInstance() {
        static Peers P;
        return &P;
    }

    as::io_service& get_io_service() {
        return *io_service_client;
    }

    void set_io_service(std::shared_ptr<as::io_service> io_service) {
        io_service_client = io_service;
    }

    std::vector<std::shared_ptr<Client> > allNeighboors() {
        return neighboors;
    }
    size_t size() {
        return neighboors.size();
    }


    std::shared_ptr<Client> operator [] (int i) {
        if (i >= size()) {
            throw std::out_of_range (
                    (boost::format("neighboors out of range : %i is larger than size %i") % i % size()).str()
            );
        }
        return neighboors[i];
    }
/*
    bool addNeighboor(client& C) {
        neighboors.push_back(C.ptr());
        return true;
    }
*/
    bool addNeighboor(std::shared_ptr<Client>& C);
    bool addNeighboor(std::string& id, std::shared_ptr<Client>& C) {
        neighboorById.emplace(id, C);
        return true;
    }
    std::list<std::string> getAllNeighboorId() {
        std::list<std::string> dsts;
        for (auto && n : neighboorById) {
            dsts.push_back(n.first);
        }
        return std::move(dsts);
    }
/*
    bool rmNeighboor(client& C) {
        neighboors.erase(std::remove_if(neighboors.begin(), neighboors.end(),
                                        [&](std::shared_ptr<client> local) { return (*local == C);}),
                         neighboors.end());
        return true;
    }
*/

    void initDist();

    void addEdge(std::string& srcId, std::string& dstId) {
        dist[std::make_pair(srcId, dstId)] = 1;
        dist[std::make_pair(dstId, srcId)] = 1;
    }

    void calcSPT();

    bool rmNeighboor(std::shared_ptr<Client>& C);

    template<typename Callable>
    void forEachClient(Callable&& func) {
        for (auto&& client : neighboors) {
            // TODO : client is availible
            func(client);
        }
    }

    void setBcastMode(m_bcast_mode mode) {
        bcastMode = mode;
    }

    m_bcast_mode getBcastMode() {
        return bcastMode;
    }

    std::multimap<std::string, std::shared_ptr<Client> >& getBcastList() {
        return bcastList;
    }
    LRUSet<std::string> delivered_msg;
private:
    Peers() { bcastMode = m_FLOOD;}
    std::vector<std::shared_ptr<Client> > neighboors;
    std::map<std::string, std::shared_ptr<Client> > neighboorById;
    std::multimap<std::string, std::shared_ptr<Client> > bcastList;
    std::shared_ptr<as::io_service>  io_service_client;
    std::map<std::pair<std::string, std::string>, int> dist;
    m_bcast_mode bcastMode;
};


#endif //RAN_EXP_PEERS_H
