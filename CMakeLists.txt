cmake_minimum_required(VERSION 3.9)
project(ran_exp)

set(CMAKE_CXX_STANDARD 17)
set(OPENSSL_ROOT_DIR /usr/local/Cellar/openssl/1.0.2p)
find_library(CryptoPP REQUIRED)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g")
find_package(openssl REQUIRED)
find_package (Boost COMPONENTS system filesystem serialization thread REQUIRED)
find_package(libmongocxx REQUIRED PATHS /usr/local/Cellar/mongo-cxx-driver/3.3.1/lib/cmake/libmongocxx-3.3.1)

include_directories (${Boost_INCLUDE_DIR} ${OPENSSL_INCLUDE_DIR} ${LIBMONGOCXX_INCLUDE_DIRS})
set(SOURCE_FILES main.cpp src/network/peers.cpp src/network/peers.hpp src/network/client.cpp src/network/client.hpp src/network/message.cpp src/network/message.hpp src/network/msg_queue.cpp src/network/msg_queue.hpp src/network/tcp_server.cpp src/network/tcp_server.hpp src/network/tcp_connection.cpp src/network/tcp_connection.hpp src/tools/conf.cpp src/tools/conf.hpp src/tools/json.hpp src/tools/manager.cpp src/tools/manager.hpp src/crypto/crypto.cpp src/crypto/crypto.hpp src/tools/Actor.hpp src/tools/actor.cpp src/tools/actor.hpp src/webapi/webapi.cpp src/webapi/webapi.hpp)

add_subdirectory(src/webapi/oatpp)

add_executable(ran_exp ${SOURCE_FILES})
target_link_libraries(ran_exp PUBLIC oatpp ${Boost_LIBRARIES} ${Boost_FILESYSTEM_LIBRARY} ${Boost_SYSTEM_LIBRARY} cryptopp ${OPENSSL_LIBRARIES} ${LIBMONGOCXX_LIBRARIES})

#get_cmake_property(_variableNames VARIABLES)
#list (SORT _variableNames)
#foreach (_variableName ${_variableNames})
#    message(STATUS "${_variableName}=${${_variableName}}")
#endforeach()