//
// Created by Blink on 2018/5/21.
//

#ifndef RAN_EXP_MANAGER_HPP
#define RAN_EXP_MANAGER_HPP

#include "../network/message.hpp"
#include "../network/msg_queue.hpp"
#include "../network/client.hpp"
#include "../crypto/crypto.hpp"
#include "actor.hpp"
#include <atomic>
#include <list>
#include "json.hpp"
#include <bsoncxx/json.hpp>
#include <bsoncxx/builder/stream/document.hpp>
#include <mongocxx/client.hpp>
#include <mongocxx/stdx.hpp>
#include <mongocxx/uri.hpp>
#include <mongocxx/instance.hpp>
#include <optional>
//#include "../network/peers.hpp"

class Client;
namespace manager {
    using json = nlohmann::json;
    struct PlainShare {
        std::string share;
        std::string senderId;
        std::string sigR;
        std::string sigS;
    };
    const int RAN_N = 16;
    extern int actorN; // Count of actors
    extern std::vector<Actor> actors;
    extern std::string version;
    extern int rateLimit;
    extern bool enableApi;
    struct ActorSig {
        std::string id;
        std::string sigR;
        std::string sigS;
    };
    struct Result {
        int globalTurn;
        unsigned int pseRes[RAN_N];
        unsigned int result[RAN_N];
        std::list<ActorSig> sigs;
    };
    typedef std::list<Result> ResChain;


    extern MsgQueue<std::shared_ptr<Message> > recvMsgQ;
    // my id
    extern std::string myId;
    std::string getMyId();


    std::list<std::string> getAllActorsId();
    // receive a message (block)
    std::shared_ptr<Message> recv();

    // send msg to client c (async)
    void send(std::shared_ptr<Client> c, std::shared_ptr<Message> msg);

    // broadcast a message (async)
    void bsend(std::shared_ptr<Message> msg);

    // 保持主动连接 存活检测
    void connectionHelper();

    std::string getRandomOracle();

    extern std::atomic<bool> allActorsReady;

    void run();

    ResChain getLatestResult();
    Result getSimpleResult();
    std::string resultToJsonStr(Result& latestRes);
    std::string resultChainToJsonStr(ResChain latestRes);
    void initDB(std::string mongoUri, std::string dbName, std::string collName);
    std::optional<std::string> getHistoryResult(int round);
};

#endif //RAN_EXP_MANAGER_HPP
