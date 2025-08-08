#include "rpcserver.h"

#include <string>

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>

#include <kj/debug.h>

#include <capnp/ez-rpc.h>
#include <capnp/message.h>

#include "implementation.hpp"

namespace collat::rpc {

    RpcServer::RpcServer(unsigned short port) {
        auto logger = spdlog::stdout_color_mt("collat-rpc");
        logger->info("Starting RPC server on port {}...", port);

        
        capnp::EzRpcServer server(kj::heap<CollatServerImpl>(), "*", port);

        
        
        
        while(1){}
    }

}