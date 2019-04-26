//
// Created by Blink on 2018/5/10.
//

#include "peers.hpp"
#include "../tools/manager.hpp"
bool Peers::rmNeighboor(std::shared_ptr<Client> &C) {
neighboors.erase(std::remove_if(neighboors.begin(), neighboors.end(),
                                [&](std::shared_ptr<Client> local) { return (*local == *C);}),
        neighboors.end());
return true;
}

bool Peers::addNeighboor(std::shared_ptr<Client>& C) {
    neighboors.push_back(C);
    for (std::shared_ptr<Client>& client : allNeighboors()) {
        std::cout << client->isConnectTo() << std::endl;
    }
    return true;
}

void Peers::initDist() {
    auto allActors = manager::getAllActorsId();
    for (auto&& srcId : allActors) {
        for (auto&& dstId : allActors) {
            if (srcId == dstId) {
                dist.emplace(std::make_pair(srcId, dstId), 0);
            }
            else {
                dist.emplace(std::make_pair(srcId, dstId), 0x7fffffff / 3);
            }
        }
        //dist.emplace(std::make_pair(srcId, manager::getMyId()), 1);
        //dist.emplace(std::make_pair(manager::getMyId(), srcId), 1);
    }
}

void Peers::calcSPT() {

    auto allActors = manager::getAllActorsId();


    for (auto&& i : allActors) {
        for (auto&& u : allActors) {
            for (auto&& v : allActors) {
                if (dist[std::make_pair(u, v)] > dist[std::make_pair(u, i)] + dist[std::make_pair(i, v)]) {
                    dist[std::make_pair(u, v)] = dist[std::make_pair(u, i)] + dist[std::make_pair(i, v)];
                }
            }
        }
    }

    for (auto&& u : allActors) {
        for (auto&& v : allActors) {
            std::cout << "[DEBUG] Dist of " << u << " " << v << " : " << dist[std::make_pair(u, v)] << std::endl;
        }
    }

    auto allNeighboors = getAllNeighboorId();

    for (auto&& st : allActors) {
        for (auto&& ed : allActors) {
            if (st == ed || st == manager::getMyId() || ed == manager::getMyId()) {
                continue;
            }
            if (dist[std::make_pair(st, ed)] == dist[std::make_pair(st, manager::getMyId())]
                                                + dist[std::make_pair(manager::getMyId(), ed)]) {
                for (auto&& nxt : allNeighboors) {
                    if (dist[std::make_pair(nxt, ed)] == dist[std::make_pair(manager::getMyId(), ed)] - 1) {
                        bcastList.insert({st, neighboorById[nxt]});
                        std::cout << "[DEBUG] should cast: " << st << " " << nxt << std::endl;
                        break;
                    }
                }
            }
        }
    }

}