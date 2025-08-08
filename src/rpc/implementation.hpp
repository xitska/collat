#pragma once

#include "schema/collat-rpc.capnp.h"

#include <kj/debug.h>
#include <capnp/ez-rpc.h>
#include <capnp/message.h>

#include "hv.h"

namespace collat::rpc {
    class CollatServerImpl final: public Collat::Server {
        kj::Promise<void> doFastHypercall(DoFastHypercallContext context) override {
            auto params = context.getParams();
            auto results = context.getResults();

            

            auto callCode = static_cast<uint32_t>(params.getCallcode());
            if(callCode >= COLLAT_HV_HYPERCALL_LIMIT) 
                KJ_FAIL_REQUIRE("Invalid hypercall code");

            auto data = params.getInput();

            void* outputData = malloc(results.getOutput().size());
            uint64_t repCnt = 0;

            hv::fast_hypercall(
                callCode,
                reinterpret_cast<const void*>(data.begin()),
                data.size(),
                outputData,
                results.getOutput().size(),
                &repCnt
            );

            results.setRepcnt(repCnt);
            
            return kj::READY_NOW;
        }

        kj::Promise<void> callKernel(CallKernelContext context) override {
            auto params = context.getParams();
            auto results = context.getResults();

            std::string moduleName = params.getModule().cStr();
            std::string functionName = params.getFunction().cStr();
            auto args = params.getArguments();

            return kj::NEVER_DONE;
        }

        kj::Promise<void> getKernelModuleBase(GetKernelModuleBaseContext context) override {
            auto params = context.getParams();
            auto results = context.getResults();
            
            std::string moduleName = params.getModuleName().cStr();
            
            void* moduleBase = kmodule::get_base(moduleName);
            
            results.setModuleBase(
                reinterpret_cast<uint64_t>(moduleBase)
            );
            
            return kj::READY_NOW;
        }

        kj::Promise<void> readKernel(ReadKernelContext context) override {
            auto params = context.getParams();
            auto results = context.getResults();
            
            auto size = params.getSize();
            auto address = reinterpret_cast<void*>(
                params.getAddress()
            );

            auto ioring = kernel::get_ioring();
            if(ioring == nullptr)
                KJ_FAIL_REQUIRE("Kernel ioring not initialized... Exploit failed?");

            auto data = kj::heapArray<capnp::byte>(size);

            ioring->raw_read_internal(
                address,
                data.begin(),
                size
            );

            results.setData(data);

            return kj::READY_NOW;
        }
    };
}