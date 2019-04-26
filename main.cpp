#include <iostream>
#include "src/tools/manager.hpp"
#include "src/tools/conf.hpp"
#include "src/network/tcp_server.hpp"
#include <thread>
#include <optional>
#include "src/webapi/webapi.hpp"

//namespace as = boost::asio;
void run() {
    Conf::getInstance("config.json")->ParseClients();
    Conf::getInstance("config.json")->ParseDBInfo();
    Conf::getInstance("config.json")->ParseRateLimit();
    std::cout << "Init done." << std::endl;
    manager::connectionHelper();
    manager::run();
}

void startIO(std::shared_ptr<as::io_service> io_service) {
    try {
        io_service->run();
    } catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
    }
}


int main() {
    std::cout << "Hello, World!" << std::endl;
    std::shared_ptr<as::io_service> io_service(new as::io_service);
    std::shared_ptr<as::io_service> io_service2(new as::io_service);
    TcpServer *server = NULL;
    int portNum = Conf::getInstance("config.json")->ParsePort();
    server = new TcpServer(*io_service, portNum);
    Peers::getInstance()->set_io_service(io_service2);
    auto thread1 = std::thread(&startIO, std::ref(io_service));
    auto thread2 = std::thread(&startIO, std::ref(io_service2));
    thread1.detach();
    thread2.detach();
    if (auto apiPort = Conf::getInstance("config.json")->ParseApiPort()) {
        webapi::start(apiPort.value());
    }
    run();

    return 0;
}