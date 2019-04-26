//
// Created by Blink on 2018/5/21.
//

#include <string.h>
#include "manager.hpp"
#include <random>
#include "optional"

namespace manager {

    // for DB
    using bsoncxx::builder::stream::close_array;
    using bsoncxx::builder::stream::close_document;
    using bsoncxx::builder::stream::document;
    using bsoncxx::builder::stream::finalize;
    using bsoncxx::builder::stream::open_array;
    using bsoncxx::builder::stream::open_document;

    std::string version; // api version
    int rateLimit;
    MsgQueue<std::shared_ptr<Message> > recvMsgQ;
    MsgQueue<std::string> waitSignQ;
    MsgQueue<std::pair<std::string, ECDSA_SIG*> > signResQ;
    std::map<std::string, std::string> sigRes;
    std::mt19937 fakeRNG(0);
    std::uniform_int_distribution<std::mt19937::result_type> fakeRandomDist;
    const int TURN_PER_ROUND = 100;
    std::atomic<int> globalTurn(0);
    int currentTurn = 0;
    std::mutex resultMutex;
    std::string currentSeed;
    unsigned int ranResult[RAN_N];
    unsigned int pseResult[RAN_N];
    bool enableApi;
    // for DB
    mongocxx::instance instance{};
    std::shared_ptr<mongocxx::client> dbClient;
    std::shared_ptr<mongocxx::database> db;
    std::shared_ptr<mongocxx::collection> dbColl;


    std::shared_ptr<Message> recvedMsg;
    std::shared_ptr<AckMessage> AM;
    std::shared_ptr<SharesMessage> SM;
    std::shared_ptr<PlainSharesMessage> PSM;
    std::shared_ptr<SyncMessage> SynM;
    double all_elapsed_seconds = 0;
    double all_enc_seconds = 0;
    double all_dec_seconds = 0;
    double all_en_share_seconds = 0;
    double all_de_share_seconds = 0;
    double all_recv_seconds = 0;
    double all_sign_seconds = 0;




    std::string myId;
    std::string getMyId() {
        return myId;
    }
    int actorN = 0; // Count of actors
    std::vector<Actor> actors;

    ResChain latestRes;


    void initDB(std::string mongoUri, std::string dbName, std::string collName) {
        mongocxx::uri uri(mongoUri);
        dbClient = std::make_shared<mongocxx::client>(uri);
        db = std::make_shared<mongocxx::database>(std::move((*dbClient)[dbName]));
        dbColl = std::make_shared<mongocxx::collection>(std::move((*db)[collName]));
        dbColl->drop();
        bsoncxx::document::view_or_value doc =
                bsoncxx::from_json("{\"doc_type\": \"lastest_round\", \"round\": -1}");
        bsoncxx::stdx::optional<mongocxx::result::insert_one> result = dbColl->insert_one(doc);
        std::cout << "[DEBUG] inited db connection" << std::endl;
    }

    std::string resultToJsonStr(Result& latestRes) {
        json res;
        res["globalTurn"] = latestRes.globalTurn;
        res["result"] = std::vector<unsigned int>(latestRes.result,
                                                   latestRes.result + sizeof(latestRes.result) / sizeof(latestRes.result[0]));
        res["doc_type"] = "simple_result";
        res["version"] = version;
        res["status"] = true;
        return res.dump();
    }

    std::string resultChainToJsonStr(ResChain latestRes) {
        json res;
        std::vector<json> resChainJson;
        int round = 0;
        for (auto&& res : latestRes) {
            json resJson;
            round = (res.globalTurn - 1) / 100;
            resJson["globalTurn"] = res.globalTurn;
            resJson["result"] = std::vector<unsigned int>(res.result,
                                                           res.result + sizeof(res.result) / sizeof(res.result[0]));
            resJson["pseResult"] = std::vector<unsigned int>(res.pseRes,
                                                              res.pseRes + sizeof(res.pseRes) / sizeof(res.pseRes[0]));
            std::vector<json> sigsJson;
            for (auto&& sig : res.sigs) {
                json sigJson;
                sigJson["id"] = sig.id;
                sigJson["sig_s"] = sig.sigS;
                sigJson["sig_r"] = sig.sigR;
                sigsJson.push_back(sigJson);
            }
            resJson["sigs"] = sigsJson;
            resChainJson.push_back(resJson);
        }
        res["round"] = round;
        res["status"] = true;
        res["doc_type"] = "result";
        res["version"] = version;
        res["chain"] = resChainJson;
        return res.dump();
    }
    std::optional<std::string> getHistoryResult(int turn) {
        if (turn >= globalTurn.load()) {
            return std::nullopt;
        }
        if ((turn - 1) / TURN_PER_ROUND == (globalTurn.load() - 1) / TURN_PER_ROUND) {
            return resultChainToJsonStr(getLatestResult());
        }
        int round = (turn - 1) / TURN_PER_ROUND;
        std::lock_guard<std::mutex> lck(resultMutex);
        bsoncxx::document::view_or_value filter =
                bsoncxx::from_json("{\"doc_type\" : \"result\", \"round\" : " + std::to_string(round) + "}");

        bsoncxx::stdx::optional<bsoncxx::document::value> maybe_result =
                dbColl->find_one(filter);
        if(maybe_result) {
            return bsoncxx::to_json(*maybe_result);
        }
        return std::nullopt;
    }

    Result getSimpleResult() {
        std::lock_guard<std::mutex> lck(resultMutex);
        return latestRes.back();
    }

    ResChain getLatestResult() {
        std::lock_guard<std::mutex> lck(resultMutex);
        return latestRes;
    }

    void initTurn() {
        for (int i = 0; i < RAN_N; i ++) {
            ranResult[i] = pseResult[i] = fakeRandomDist(fakeRNG);
        }
        return ;
    }

    bool verifySig(std::string msg, std::string sigStr, std::string id) {
        if (id == myId) {
            return true;
        }
        std::string sigR = sigStr.substr(0, 64);
        std::string sigS = sigStr.substr(65, 64);
        ECDSA_SIG * sig = ECDSA_SIG_new();

        BN_hex2bn(& sig->s, sigS.c_str());
        BN_hex2bn(& sig->r, sigR.c_str());
        for (auto && actor : actors) {
            if (id == actor.getId()) {
                bool res = actor.verifySig(msg, *sig);
                ECDSA_SIG_free(sig);
                return res;
            }
        }
    }

    void addSigToRes(std::string& actorId, std::string& sig) {
        if (!verifySig(currentSeed, sig, actorId)) {
            std::cout << "[DEBUG] Verify Failure " << std::endl;
            std::cout << actorId << std::endl;
            std::cout << sig << std::endl;
            std::cout << currentSeed << std::endl;
            exit(0);
        }
        for (int i = 0; i < (RAN_N >> 1); i ++) {
            std::string s = sig.substr(i * 8, 8);
            unsigned int num = std::stoul(s, 0, 16);
            ranResult[i] ^= num;
        }
        for (int i = 0; i < (RAN_N >> 1); i ++) {
            std::string s = sig.substr(i * 8 + 65, 8);
            unsigned int num = std::stoul(s, 0, 16);
            ranResult[i + (RAN_N >> 1)] ^= num;
        }
        sigRes[actorId] = sig;
        return ;
    }

    void handleResult() {
        Result currentRes;
        currentRes.globalTurn = globalTurn.load();
        std::copy(std::begin(ranResult), std::end(ranResult), std::begin(currentRes.result));
        std::copy(std::begin(pseResult), std::end(pseResult), std::begin(currentRes.pseRes));
        ActorSig actorSig;
        for (auto&& sig : sigRes) {
            actorSig.id = sig.first;
            actorSig.sigR = sig.second.substr(0, 64);
            actorSig.sigS = sig.second.substr(65, 64);
            currentRes.sigs.push_back(actorSig);
        }
        if (currentRes.globalTurn % 100 == 1) {
            std::lock_guard<std::mutex> lck(resultMutex);
            if (enableApi) {
                auto resChainStr = resultChainToJsonStr(latestRes);
                bsoncxx::document::view_or_value doc = bsoncxx::from_json(resChainStr);
                dbColl->insert_one(doc);

                doc = bsoncxx::from_json("{\"doc_type\": \"lastest_round\"}");
                dbColl->delete_many(doc);
                int last_round = (currentRes.globalTurn - 1) / 100;
                doc = bsoncxx::from_json("{\"doc_type\": \"lastest_round\", \"round\": " + std::to_string(last_round) + "}");
                dbColl->insert_one(doc);

            }
            latestRes.clear();
        }
        {
            std::lock_guard<std::mutex> lck(resultMutex);
            latestRes.push_back(currentRes);
        }

    }



    std::list<std::string> getAllActorsId() {
        std::list<std::string> actorsId;
        for (auto&& actor : actors) {
            actorsId.push_back(actor.getId());
        }
        actorsId.push_back(getMyId());
        return std::move(actorsId);
    }
    // receive a message (block)
    std::shared_ptr<Message> recv() {
        std::shared_ptr<Message> msg;
        recvMsgQ.pop(msg);
        return msg;
    }


    // send msg to client c (async)
    void send(std::shared_ptr<Client> c, std::shared_ptr<Message> msg) {
        c->send(msg);
    }


    // broadcast a message (async)
    void bsend(std::shared_ptr<Message> msg) {
        Peers::getInstance()->forEachClient(std::bind(manager::send, std::placeholders::_1, msg));
        return ;
    }

    void connectionHelper() {
        for (std::shared_ptr<Client> client : Peers::getInstance()->allNeighboors()) {
            std::cout << "[DEBUG MANAGER] use count of client: " << client.use_count() << std::endl;
            if (client->isConnectTo()) {
                while (!client->connect()) {
                    std::cout << "[DEBUG MANAGER] connect failed" << std::endl;
                    std::cout << "[DEBUG MANAGER] will connect: " << client->getIP() << ":" << client->getPort() << std::endl;
                    std::this_thread::sleep_for (std::chrono::seconds(2));
                }

            }
        }

    }


    std::string getRandomOracle() {
        int turn = globalTurn.load();
        if (turn % 100 == 0) {
            return std::to_string(turn / 100);
        }
        return std::to_string(ranResult[0]);
    }

    std::atomic<bool> allActorsReady(false); //everyone knows that everyone knows everyone is ready
    std::atomic<bool> iAmReady(false); // I know that everyone is ready
    void sendSync() {
        bool lastSend = 0;
        while (!allActorsReady.load() || !lastSend) {
            long now = std::chrono::time_point_cast<std::chrono::seconds>(std::chrono::system_clock::now())
                    .time_since_epoch().count();
            SyncMessage sm(m_sync, 0, std::string("0.0.0.0"), myId, now, iAmReady.load());
            if (allActorsReady.load()) {
                lastSend = true;
            }
            bsend(std::make_shared<SyncMessage>(sm));
            std::this_thread::sleep_for (std::chrono::seconds(2));
        }
    }


    std::string toSigString(char* sig_r, char* sig_s) {
        std::string strR = std::string(sig_r);
        std::string strS = std::string(sig_s);
        return std::string(64 - strR.length(), '0') + strR + "/" + std::string(64 - strS.length(), '0') + strS;
    }

    void waitOtherNodesUp() {
        auto sendSyncThread = std::thread(&sendSync);
        bool actorOnline[actorN];
        bool actorReady[actorN];
        int actorOnlineN = 0;
        int actorReadyN = 0;
        memset(actorOnline, 0, sizeof actorOnline);
        memset(actorReady, 0, sizeof actorReady);
        while (!allActorsReady.load()) {
            recvedMsg = recv();
            if (recvedMsg->type != m_sync) {
                continue;
            }
            SynM = std::dynamic_pointer_cast<SyncMessage>(recvedMsg);
            std::cout << "[DEBUG SYN] from: " << SynM->sender_id << " ready: " << SynM->ready << std::endl;
            for (int i = 0; i < actorN; i++) {
                if (actors[i].getId() == SynM->sender_id) {
                    if (!actorOnline[i]) {
                        actorOnline[i] = true;
                        actorOnlineN++;
                        if (actorOnlineN == actorN) {
                            iAmReady.store(true);
                        }
                    }
                    std::cout << "[DEBUG SYN] actor " << SynM->sender_id << " ready: " << actorReady[i] << std::endl;
                    if ((!actorReady[i]) && SynM->ready) {
                        actorReady[i] = true;
                        actorReadyN ++;
                        std::cout << "[DEBUG SYN] actorReadyN: " << actorReadyN << " actorN: " << actorN << std::endl;
                        if (actorReadyN == actorN) {
                            std::cout << "[DEBUG SYN] all actors readyed " << std::endl;
                            allActorsReady.store(true);
                        }
                    }
                }
            }
        }

        sendSyncThread.join();
    }

    void changeBroadcastMode() {
        {
            EdgeMessage edgeM(m_edge, 0, std::string("0.0.0.0"), myId);
            edgeM.dsts = Peers::getInstance()->getAllNeighboorId();
            bsend(std::make_shared<EdgeMessage>(edgeM));
        }

        Peers::getInstance()->initDist();
        int edgeCnt = 0;
        bool recvedEdge[actorN];
        memset(recvedEdge, 0, sizeof recvedEdge);
        std::shared_ptr<EdgeMessage> edgeM;

        while (edgeCnt < actorN) {
            recvedMsg = recv();
            if (recvedMsg->type != m_edge) {
                continue;
            }
            edgeM = std::dynamic_pointer_cast<EdgeMessage>(recvedMsg);
            std::string src = edgeM->src;
            for (int i = 0; i < actorN; i++) {
                if (actors[i].getId() == src && !recvedEdge[i]) {
                    recvedEdge[i] = true;
                    edgeCnt ++;
                    std::cout << "[DEBUG] Received Edge: " << edgeM->src << std::endl;
                    for (auto && dst : edgeM->dsts) {
                        std::cout << dst << " ";
                        Peers::getInstance()->addEdge(src, dst);
                    }
                    std::cout << std::endl;
                }
            }

        }

        Peers::getInstance()->calcSPT();
        Peers::getInstance()->setBcastMode(m_SPT);
    }

    void registerSigner() {
        int concurentThreadsSupported = std::thread::hardware_concurrency() - 2;
        int nThread = 1;//std::max(concurentThreadsSupported - 3, 1);
        std::vector<std::thread> signWorkers;
        for (int i = 0; i < nThread; i++) {
            signWorkers.push_back(std::thread([&]() {
                std::string msg;
                while (true) {
                    waitSignQ.pop(msg);
                    signResQ.push(std::make_pair(msg, Crypto::sign(msg)));
                }
            }));
        }
        std::for_each(signWorkers.begin(), signWorkers.end(), [](std::thread &t) {
            t.detach();
        });
    }
    void run() {

        /*
        while (true) {
            AckMessage AM(m_ack, 64, std::string("0.0.0.0"), myId);
            bsend(std::make_shared<AckMessage>(AM));

            std::cout << "[DEBUG] Before get ACK message: " << std::endl;
            recvedMsg = recv();
            std::cout << "[DEBUG] Hope to get ACK message: " <<  recvedMsg->type << std::endl;

            if (recvedMsg->type == m_ack) {
                std::shared_ptr<AckMessage> AM = std::dynamic_pointer_cast<AckMessage>(recvedMsg);
                std::string senderId = AM->sender_id;
                std::cout << "[DEBUG] Received Ack Message from " <<  senderId << std::endl;
            }

            sleep(5);
        }
        */

        //actorN = 1;
        actorN = actors.size();

        waitOtherNodesUp();

        changeBroadcastMode();

        registerSigner();





        while (true) {
            currentTurn ++;
            if (currentTurn % 1000 == 1) {
                std::cout << "[DEBUG] Currrent turn: " << currentTurn << std::endl;
            }
            auto startTime = std::chrono::system_clock::now();
            std::string seed = getRandomOracle();
            currentSeed = seed;
            initTurn();
            globalTurn ++;
            auto signStartTime = std::chrono::system_clock::now();
            auto sig = Crypto::sign(seed);
            auto signEndTime = std::chrono::system_clock::now();
            std::chrono::duration<double> elapsed_seconds = signEndTime - signStartTime;
            all_sign_seconds += elapsed_seconds.count();

            char *tmpSigR, *tmpSigS;
            tmpSigR = BN_bn2hex(sig->r);
            tmpSigS = BN_bn2hex(sig->s);
            ECDSA_SIG_free(sig);

            // split by "/"
            std::string mySig = toSigString(tmpSigR, tmpSigS);
            OPENSSL_free(tmpSigR);
            OPENSSL_free(tmpSigS);
            if (currentTurn % 1000 == 1) {
                std::cout << "Sig: " << mySig << std::endl;
            }
            auto enShareStartTime = std::chrono::system_clock::now();
            auto sharesMySig = Crypto::SecretShareBytes(mySig, (actorN + 1) / 2, actorN);
            auto enShareEndTime = std::chrono::system_clock::now();
            elapsed_seconds = enShareEndTime - enShareStartTime;
            all_en_share_seconds += elapsed_seconds.count();
            int idx = 0;
            for (auto&& share : sharesMySig) {
                waitSignQ.push(share);
            }
            SharesMessage SMToSend(m_share, currentTurn, myId, myId);

            for (int i = 0; i < actorN; i ++) {
                // Signature of share
                auto signStartTime = std::chrono::system_clock::now();
                //auto shareSig = Crypto::sign(seed);
                std::pair<std::string, ECDSA_SIG*> sharePair;
                signResQ.pop(sharePair);
                std::string share = sharePair.first;
                ECDSA_SIG* shareSig = sharePair.second;
                auto signEndTime = std::chrono::system_clock::now();
                elapsed_seconds = signEndTime - signStartTime;
                all_sign_seconds += elapsed_seconds.count();
                // Cipher of share for a actor
                auto encStartTime = std::chrono::system_clock::now();
                auto shareCipher = Crypto::base64_encode(actors[idx].enc(share));
                auto encEndTime = std::chrono::system_clock::now();

                elapsed_seconds = encEndTime - encStartTime;
                all_enc_seconds += elapsed_seconds.count();
                //std::cout << "[DEBUG] Encrypted share for id: " + actors[idx].getId() + " : " ;
                //std::cout << shareCipher << std::endl;
                //SharesMessage SMToSend(m_share, currentTurn, std::string("0.0.0.0"), shareCipher, shareSig, actors[idx].getId(), myId);
                // send(broadcast) someone's share
                //bsend(std::make_shared<SharesMessage>(SMToSend));
                Share SToSend(shareCipher, *shareSig, actors[idx].getId());
                ECDSA_SIG_free(shareSig);
                SMToSend.shares.push_back(SToSend);
                idx ++;
            }
            bsend(std::make_shared<SharesMessage>(SMToSend));
            if (currentTurn % 1000 == 1) {
                std::cout << "[DEBUG] Broadcasted encrypted shares" << std::endl;
            }





            // shares belongs to me
            std::vector<PlainShare> sharesToMe;

            bool recvedShareToMe[actorN];
            memset(recvedShareToMe, 0, sizeof recvedShareToMe);

            bool acked[actorN];
            memset(acked, 0, sizeof acked);
            int ackN = 0;

            std::map<std::string, std::vector<std::string> > plainShares;
            std::map<std::string, bool> decryped;
            int decrypedCount = 0;
            plainShares.insert(std::make_pair<std::string, std::vector<std::string> >(getMyId(), std::vector<std::string>()));
            decryped.insert(std::make_pair<std::string, bool>(getMyId(), false));

            while (sharesToMe.size() < actorN) {
                auto recvStartTime = std::chrono::system_clock::now();
                recvedMsg = recv();
                auto recvEndTime = std::chrono::system_clock::now();
                std::chrono::duration<double> elapsed_seconds = recvEndTime - recvStartTime;
                all_recv_seconds += elapsed_seconds.count();
                if (recvedMsg->type != m_share || recvedMsg->ttl != currentTurn) {
                    if (recvedMsg->ttl > currentTurn) {
                        std::cout << "[DEBUG] got newer turn message" << std::endl;
                        recvMsgQ.push(recvedMsg);
                        continue;
                    }
                    if (recvedMsg->ttl < currentTurn) {
                        continue;
                    }
                    if (recvedMsg->type == m_ack) {
                        AM = std::dynamic_pointer_cast<AckMessage>(recvedMsg);
                        std::string senderId = AM->sender_id;
                        // TODO: verify signature
                        idx = 0;
                        for (auto&& actor : actors) {
                            if (actor.getId() == senderId) {
                                ackN += (!acked[idx]);
                                acked[idx] = true;
                                break;
                            }
                            idx ++;
                        }
                    }
                    if (recvedMsg->type == m_plainshare) {
                        std::cout << "[DEBUG] should get ack but got plainshare" << std::endl;
                        PSM = std::dynamic_pointer_cast<PlainSharesMessage>(recvedMsg);
                        for (auto && PS : PSM->plainshares) {
                            std::string senderId = PS.sender_id;
                            if (decryped[senderId]) {
                                continue;
                            }
                            plainShares[senderId].push_back(Crypto::base64_decode(PS.share));
                            if (senderId != myId && actorN < (plainShares[senderId].size() << 1) && !decryped[senderId]) {
                                auto deShareStartTime = std::chrono::system_clock::now();
                                std::string plainSig = Crypto::SecretRecoverBytes(plainShares[senderId], (actorN + 1) / 2);
                                auto deShareEndTime = std::chrono::system_clock::now();
                                elapsed_seconds = deShareEndTime - deShareStartTime;
                                all_de_share_seconds += elapsed_seconds.count();
                                addSigToRes(senderId, plainSig);
                                decrypedCount++;
                                decryped[senderId] = true;
                                if (currentTurn % 1000 == 1) {
                                    std::cout << "[DEBUG] Recovered Sig from " + senderId + " : " + plainSig << std::endl;
                                }
                            }
                        }
                    }
                    //ignore none SharesMessage
                    //std::cout << "[DEBUG] recv msg but not SharesMessage" << std::endl;
                    continue;
                }
                //std::cout << "[DEBUG POINTER] after receive, use count of recvedMsg: " << recvedMsg.use_count() << std::endl;
                //std::cout << "[DEBUG POINTER] after receive, use count of SM: " << SM.use_count() << std::endl;
                SM = std::dynamic_pointer_cast<SharesMessage>(recvedMsg);

                //std::cout << "[DEBUG POINTER] after dynamic cast, use count of recvedMsg: " << recvedMsg.use_count() << std::endl;
                //std::cout << "[DEBUG POINTER] after dynamic cast, use count of SM: " << SM.use_count() << std::endl;
                //std::cout << "[DEBUG] Received SharesMessage, sender_id: " << SM->sender_id << " receiver_id: " << SM->receiver_id
                //            << " encrypted_share: " + SM->encrypted_share  << " SigR: " << SM->sigR << " SigS: " << SM->sigS << std::endl;
                // not for me

                std::string senderId = SM->sender_id;

                // TODO : change to map for better performace
                idx = 0;
                for (auto&& actor : actors) {
                    if (!recvedShareToMe[idx] && actor.getId() == senderId) {
                        for (auto&& share: SM->shares) {
                            if (share.receiver_id != myId)
                                continue;
                            PlainShare PS;
                            PS.senderId = senderId;
                            PS.sigR = share.sigR;
                            //std::cout << "[DEBUG] Received sigR: " + PS.sigR << std::endl;
                            PS.sigS = share.sigS;
                            //std::cout << "[DEBUG] Received sigS: " + PS.sigS << std::endl;

                            std::string decoded_encrypted_share = Crypto::base64_decode(share.encrypted_share);
                            //std::cout << "[DEBUG] String Length: " << decoded_encrypted_share.length() << std::endl;

                            auto decStartTime = std::chrono::system_clock::now();
                            std::string decrypted_share = Crypto::decrypt(decoded_encrypted_share, actor.getEcdhKey());
                            auto decEndTime = std::chrono::system_clock::now();
                            std::chrono::duration<double> elapsed_seconds = decEndTime - decStartTime;
                            all_dec_seconds += elapsed_seconds.count();

                            PS.share = decrypted_share;
                            // TODO: sig
                            //PS.sig = SM->sig;
                            sharesToMe.push_back(PS);
                            recvedShareToMe[idx] = true;
                            break;
                        }

                    }
                    idx ++;
                }

            }

            //std::cout << "[DEBUG POINTER] after block, use count of recvedMsg: " << recvedMsg.use_count() << std::endl;
            //std::cout << "[DEBUG POINTER] after block, use count of SM: " << SM.use_count() << std::endl;
            if (currentTurn % 1000 == 1) {
                std::cout << "[DEBUG] Received all shares to me" << std::endl;
            }


            //sleep(5);
            // broadcast ack
            // TODO: sign for ack message (avoiding replay attack is requied)
            AckMessage AMToSend(m_ack, currentTurn, myId, myId);
            bsend(std::make_shared<AckMessage>(AMToSend));
            if (currentTurn % 1000 == 1) {
                std::cout << "[DEBUG] Broadcasted ACK" << std::endl;
            }
            //sleep(5);
            // TODO: change to map for better performance





            while ((ackN << 1) < actorN) {
                auto recvStartTime = std::chrono::system_clock::now();
                recvedMsg = recv();
                auto recvEndTime = std::chrono::system_clock::now();
                std::chrono::duration<double> elapsed_seconds = recvEndTime - recvStartTime;
                all_recv_seconds += elapsed_seconds.count();
                //std::cout << "[DEBUG POINTER] after recv AM, use count of recvedMsg: " << recvedMsg.use_count() << std::endl;
                //std::cout << "[DEBUG POINTER] after recv AM, use count of SM: " << SM.use_count() << std::endl;
                //std::cout << "[DEBUG POINTER] after recv AM, use count of AM: " << AM.use_count() << std::endl;
                if (recvedMsg->type != m_ack || recvedMsg->ttl != currentTurn) {
                    // ignore non AckMessage
                    if (recvedMsg->ttl < currentTurn) {
                        std::cout << "[DEBUG] turn: " << recvedMsg->ttl << std::endl;
                        continue;
                    }
                    if (recvedMsg->ttl > currentTurn) {
                        std::cout << "[DEBUG] got newer turn message" << std::endl;
                        recvMsgQ.push(recvedMsg);
                        continue;
                    }
                    if (recvedMsg->type == m_plainshare) {
                        std::cout << "[DEBUG] should get ack but got plainshare" << std::endl;
                        PSM = std::dynamic_pointer_cast<PlainSharesMessage>(recvedMsg);
                        for (auto && PS : PSM->plainshares) {
                            std::string senderId = PS.sender_id;
                            if (decryped[senderId]) {
                                continue;
                            }
                            plainShares[senderId].push_back(Crypto::base64_decode(PS.share));
                            if (senderId != myId && actorN < (plainShares[senderId].size() << 1) && !decryped[senderId]) {
                                auto deShareStartTime = std::chrono::system_clock::now();
                                std::string plainSig = Crypto::SecretRecoverBytes(plainShares[senderId], (actorN + 1) / 2);
                                auto deShareEndTime = std::chrono::system_clock::now();
                                elapsed_seconds = deShareEndTime - deShareStartTime;
                                all_de_share_seconds += elapsed_seconds.count();
                                addSigToRes(senderId, plainSig);
                                decrypedCount++;
                                decryped[senderId] = true;
                                if (currentTurn % 1000 == 1) {
                                    std::cout << "[DEBUG] Recovered Sig from " + senderId + " : " + plainSig << std::endl;
                                }
                            }
                        }
                    }
                    //std::cout << "[DEBUG] recv msg but not AckMessage" << std::endl;
                    continue;
                }
                AM = std::dynamic_pointer_cast<AckMessage>(recvedMsg);
                std::string senderId = AM->sender_id;
                // TODO: verify signature
                idx = 0;
                for (auto&& actor : actors) {
                    if (actor.getId() == senderId) {
                        ackN += (!acked[idx]);
                        acked[idx] = true;
                        break;
                    }
                    idx ++;
                }
            }
            if (currentTurn % 1000 == 1) {
                std::cout << "[DEBUG] ACKs enough" << std::endl;
            }




            for (auto&& actor : actors) {
                plainShares.insert(std::make_pair<std::string, std::vector<std::string> >(actor.getId(), std::vector<std::string>()));
                decryped.insert(std::make_pair<std::string, bool>(actor.getId(), false));
            }

            // broadcast all sharesToMe
            PlainSharesMessage PSMToSend(m_plainshare, currentTurn, myId);
            for (auto&& share : sharesToMe) {
                share.share = Crypto::base64_encode(share.share);
                //PlainSharesMessage PSMToSend(m_plainshare, currentTurn, std::string("0.0.0.0"), share.share, share.sigR, share.sigS, share.senderId);

                std::string senderId = share.senderId;
                plainShares[senderId].push_back(Crypto::base64_decode(share.share));
                if (senderId != myId && actorN < (plainShares[senderId].size() << 1)) {
                    auto deShareStartTime = std::chrono::system_clock::now();
                    std::string plainSig = Crypto::SecretRecoverBytes(plainShares[senderId], (actorN + 1) / 2);
                    auto deShareEndTime = std::chrono::system_clock::now();
                    elapsed_seconds = deShareEndTime - deShareStartTime;
                    all_de_share_seconds += elapsed_seconds.count();
                    addSigToRes(senderId, plainSig);
                    decrypedCount++;
                    decryped[senderId] = true;
                    if (currentTurn % 1000 == 1) {
                        std::cout << "[DEBUG] Recovered Sig from " + senderId + " : " + plainSig << std::endl;
                    }
                }
                PlainShareM PS(share.share, share.sigR, share.sigS, share.senderId);
                PSMToSend.plainshares.push_back(PS);
                //bsend(std::make_shared<PlainSharesMessage>(PSMToSend));
            }
            bsend(std::make_shared<PlainSharesMessage>(PSMToSend));




            while (decrypedCount < actorN) {
                auto recvStartTime = std::chrono::system_clock::now();
                recvedMsg = recv();
                auto recvEndTime = std::chrono::system_clock::now();
                std::chrono::duration<double> elapsed_seconds = recvEndTime - recvStartTime;
                all_recv_seconds += elapsed_seconds.count();
                if (recvedMsg->type != m_plainshare || recvedMsg->ttl != currentTurn) {
                    // ignore non plainshare

                    if (recvedMsg->ttl > currentTurn) {
                        std::cout << "[DEBUG] got newer turn message" << std::endl;
                        recvMsgQ.push(recvedMsg);
                        continue;
                    }
                    //std::cout <<"[DEBUG] recv msg but not PlainShareMessage" << std::endl;
                    continue;
                }
                PSM = std::dynamic_pointer_cast<PlainSharesMessage>(recvedMsg);
                for (auto && PS : PSM->plainshares) {
                    std::string senderId = PS.sender_id;
                    if (decryped[senderId]) {
                        continue;
                    }
                    plainShares[senderId].push_back(Crypto::base64_decode(PS.share));
                    if (senderId != myId && actorN < (plainShares[senderId].size() << 1) && !decryped[senderId]) {
                        auto deShareStartTime = std::chrono::system_clock::now();
                        std::string plainSig = Crypto::SecretRecoverBytes(plainShares[senderId], (actorN + 1) / 2);
                        auto deShareEndTime = std::chrono::system_clock::now();
                        elapsed_seconds = deShareEndTime - deShareStartTime;
                        all_de_share_seconds += elapsed_seconds.count();
                        addSigToRes(senderId, plainSig);
                        decrypedCount++;
                        decryped[senderId] = true;
                        if (currentTurn % 1000 == 1) {
                            std::cout << "[DEBUG] Recovered Sig from " + senderId + " : " + plainSig << std::endl;
                        }
                    }
                }

            }
            addSigToRes(myId, mySig);
            auto endTime = std::chrono::system_clock::now();
            elapsed_seconds = endTime - startTime;
            if (currentTurn != 1) {
                all_elapsed_seconds += elapsed_seconds.count();
            }
            if (currentTurn % 1000 == 1) {
                for (int i = 0; i < RAN_N; i ++) {
                    std::cout << ranResult[i] << " ";
                }
                std::cout << std::endl;
                std::cout << "elapsed time: " << elapsed_seconds.count() << "s" << std::endl;
                std::cout << "all elapsed time: " << all_elapsed_seconds << "s" << std::endl;
                std::cout << "all encrypt elapsed time: " << all_enc_seconds << "s" << std::endl;
                std::cout << "all decrypt elapsed time: " << all_dec_seconds << "s" << std::endl;
                std::cout << "all secret share elapsed time: " << all_en_share_seconds << "s" << std::endl;
                std::cout << "all recover secret share elapsed time: " << all_de_share_seconds << "s" << std::endl;
                std::cout << "all recv message elapsed time: " << all_recv_seconds << "s" << std::endl;
                std::cout << "all sign message elapsed time: " << all_sign_seconds << "s" << std::endl;
                Crypto::printLeaks();
            }
            handleResult();
            if (rateLimit != 0 && globalTurn.load() % rateLimit == 0) {
                std::this_thread::sleep_for (std::chrono::seconds(1));
            }
        }

    }

}
