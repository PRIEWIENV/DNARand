//
// Created by 余欣健 on 2018/8/22.
//

#include "webapi.hpp"
#include <thread>
#include "oatpp/core/base/Environment.hpp"
#include "Logger.hpp"
#include "AppComponent.hpp"
#include "Controller.hpp"
#include <iostream>



namespace webapi {
    void run(int port) {
        // Init Environment. Init object counters, and make basic sanity checks
        oatpp::base::Environment::init();
        oatpp::base::Environment::setLogger(new Logger());
        AppComponent components(port);
        auto router = components.httpRouter.getObject();
        auto myController = Controller::createShared();
        myController->addEndpointsToRouter(router);

        // create server which passes connections retrieved from ConnectionProvider to ConnectionHandler
        oatpp::network::server::Server server(components.serverConnectionProvider.getObject(),
                                              components.serverConnectionHandler.getObject());

        OATPP_LOGD("Server", "Running on port %u...", components.serverConnectionProvider.getObject()->getPort());

        // run server
        server.run();
        oatpp::base::Environment::setLogger(nullptr);
        // Output how many objects were created during application run and how many objects may have been leaked
        std::cout << "\nEnvironment:\n";
        std::cout << "objectsCount = " << oatpp::base::Environment::getObjectsCount() << "\n";
        std::cout << "objectsCreated = " << oatpp::base::Environment::getObjectsCreated() << "\n\n";

        oatpp::base::Environment::destroy();
    }

    void start(int port) {
        auto T = std::thread(&run, port);
        T.detach();
    }
}