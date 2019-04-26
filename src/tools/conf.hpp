//
// Created by Blink on 2018/5/15.
//

#ifndef RAN_EXP_CONF_HPP
#define RAN_EXP_CONF_HPP

#include "json.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <fstream>
#include <boost/filesystem.hpp>
#include <boost/asio.hpp>
#include <utility>
#include <optional>
#include "../network/peers.hpp"
#include "actor.hpp"


namespace as = boost::asio;
using json = nlohmann::json;
class Conf {
public:
    Conf(Conf const&) = delete;
    void operator = (Conf const&) = delete;
    static Conf* getInstance(std::string filename) {
        static Conf C(std::move(filename));
        return &C;
    }
    void ParseRateLimit() const {
        auto rateLimit = configJson["rateLimit"].get<int>();
        manager::rateLimit = rateLimit;
    }
    void ParseClients() const {
        auto peersList = configJson["peers"];
        auto myId = configJson["id"].get<std::string>();
        manager::myId = myId;
        try {
            Crypto::importPrivKey(Crypto::base64_decode(configJson["privateKey"].get<std::string>()));
        } catch (const std::exception &e) {
            std::cout << e.what() << std::endl;
            exit(0);
        }
        std::cout << peersList << std::endl;
        for (auto& peer : peersList) {
            std::cout << peer << std::endl;
            auto ip = as::ip::address::from_string(peer["ip"].get<std::string>());
            try {
                auto publicKey = Crypto::base64_decode( peer["publicKey"].get<std::string>());
                auto id = peer["id"].get<std::string>();
                Actor ac(id, publicKey);
                manager::actors.push_back(ac);
            } catch (const std::exception &e) {
                std::cout << e.what() << std::endl;
                exit(0);
            }

            auto connectTo = peer["connectTo"].get<bool>();
            int port = peer["port"].get<int>();
            if (connectTo) {
                std::shared_ptr<Client> newClient = Client::create(ip, port, connectTo, Peers::getInstance()->get_io_service());
                Peers::getInstance()->addNeighboor(newClient);
            }
            //std::cout << ip << ' ' << publicKey << ' ' << connectTo << std::endl;
        }
    }
    void ParseDBInfo() const {
        auto apiServer = configJson["apiServer"];
        auto enable = apiServer["enable"].get<bool>();
        if (!enable) {
            manager::enableApi = false;
            return ;
        }
        auto dbUri = apiServer["dbUri"].get<std::string>();
        auto dbName = apiServer["dbName"].get<std::string>();
        auto dbColl = apiServer["dbColl"].get<std::string>();

        manager::enableApi = true;
        manager::initDB(dbUri, dbName, dbColl);
    }
    int ParsePort() const {
        int port = configJson["port"].get<int>();
        return port;
    }
    void ParseKeys() const {
        auto profile = configJson["profile"];
        auto pubKey = profile["publicKey"].get<std::string>();
        auto privKey = profile["privateKey"].get<std::string>();
    }

    std::optional<int> ParseApiPort() const {
        auto apiServer = configJson["apiServer"];
        auto enable = apiServer["enable"].get<bool>();
        if (!enable) {
            return std::nullopt;
        }
        auto version = apiServer["version"].get<std::string>();
        manager::version = version;
        int port = apiServer["httpPort"].get<int>();
        return port;
        return std::nullopt;
    }
private:
    Conf(std::string _filename): filename(std::move(_filename)) {
        boost::filesystem::path tmp(filename);
        if (!boost::filesystem::exists(tmp)) {
            throw std::runtime_error("Could not open file" + filename);
        }
        std::ifstream ifs(filename);
        std::string stringToParse((std::istreambuf_iterator<char>(ifs)),
                                  std::istreambuf_iterator<char>());
        configJson = json::parse(stringToParse);
    }
    std::string filename;
    json configJson;
};


#endif //RAN_EXP_CONF_HPP
