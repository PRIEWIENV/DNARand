#include "oatpp/web/server/api/ApiController.hpp"
#include "oatpp/core/macro/codegen.hpp"
#include "../tools/manager.hpp"
#include "../tools/json.hpp"

class Controller : public oatpp::web::server::api::ApiController {
protected:
    Controller(const std::shared_ptr<ObjectMapper>& objectMapper)
            : oatpp::web::server::api::ApiController(objectMapper)
    {}
public:

    static std::shared_ptr<Controller> createShared(const std::shared_ptr<ObjectMapper>& objectMapper = nullptr){
        return std::shared_ptr<Controller>(new Controller(objectMapper));
    }
#include OATPP_CODEGEN_BEGIN(ApiController)
    ENDPOINT("GET", "/", root) {
        return createResponse(Status::CODE_200, "Hello World!");
    }
    ENDPOINT("GET", "/simple_latest", simplelatest) {
        auto&& latestRes = manager::getSimpleResult();
        std::string ret =  manager::resultToJsonStr(latestRes);
        return createResponse(Status::CODE_200, oatpp::String(ret.c_str()));
    }
    ENDPOINT("GET", "/history/{param}", history, PATH(Int32, param)) {
        if (auto res = manager::getHistoryResult(param)) {
            return createResponse(Status::CODE_200, res.value().c_str());
        }
        return createResponse(Status::CODE_404, "{\"status\": false}");
    }
    ENDPOINT("GET", "/latest", latest) {
        auto&& latestRes = manager::getLatestResult();
        std::string ret = manager::resultChainToJsonStr(latestRes);
        return createResponse(Status::CODE_200, oatpp::String(ret.c_str()));
    }
#include OATPP_CODEGEN_END(ApiController)

};