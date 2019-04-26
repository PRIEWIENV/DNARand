#include "oatpp/web/server/HttpConnectionHandler.hpp"
#include "oatpp/web/server/HttpRouter.hpp"
#include "oatpp/network/server/SimpleTCPConnectionProvider.hpp"

#include "oatpp/core/macro/component.hpp"

/**
 *  Class which creates and holds Application components and registers components in oatpp::base::Environment
 *  Order of components initialization is from top to bottom
 */
class AppComponent {
public:
    int port;
    AppComponent(int _port): port(_port) {}
    /**
     *  Create ConnectionProvider component which listens on the port
     */
    OATPP_CREATE_COMPONENT(std::shared_ptr<oatpp::network::ServerConnectionProvider>, serverConnectionProvider)([this] {
        return oatpp::network::server::SimpleTCPConnectionProvider::createShared(port);
    }());

    /**
     *  Create Router component which implements routing of incoming http requests
     */
    OATPP_CREATE_COMPONENT(std::shared_ptr<oatpp::web::server::HttpRouter>, httpRouter)([] {
        return oatpp::web::server::HttpRouter::createShared();
    }());

    /**
     *  Create ConnectionHandler component which uses Router component to route requests
     */
    OATPP_CREATE_COMPONENT(std::shared_ptr<oatpp::network::server::ConnectionHandler>, serverConnectionHandler)([] {
        OATPP_COMPONENT(std::shared_ptr<oatpp::web::server::HttpRouter>, router); // get Router component
        return oatpp::web::server::HttpConnectionHandler::createShared(router);
    }());
};