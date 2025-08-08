#pragma once

#ifdef COLLAT_RPC_ENABLED

#include <thread>

namespace collat::rpc {
    class RpcServer {
        private:
        std::thread _thread;
        public:
        RpcServer(unsigned short port);
    };
}

#endif // COLLAT_RPC_ENABLED