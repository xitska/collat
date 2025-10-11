cmake_minimum_required(VERSION 3.10.0)
cmake_policy(SET CMP0091 NEW)

set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded")
set(CMAKE_SYSTEM_VERSION "10.0.22621.0")
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Setup CPM
file(
  DOWNLOAD
  https://github.com/cpm-cmake/CPM.cmake/releases/download/v0.40.8/CPM.cmake
  ${CMAKE_CURRENT_BINARY_DIR}/cmake/CPM.cmake
  EXPECTED_HASH SHA256=78ba32abdf798bc616bab7c73aac32a17bbd7b06ad9e26a6add69de8f3ae4791
)
include(${CMAKE_CURRENT_BINARY_DIR}/cmake/CPM.cmake)

# Setup dependencies
CPMAddPackage(
    "gh:gabime/spdlog@1.15.3"
)

CPMAddPackage(
    NAME phnt
    GITHUB_REPOSITORY winsiderss/phnt
    GIT_TAG master
    DOWNLOAD_ONLY YES
)

# Create interface library for PHNT headers
if(phnt_ADDED)
  add_library(phnt INTERFACE)
  target_include_directories(phnt INTERFACE ${phnt_SOURCE_DIR})
  
  # Add any necessary compile definitions
  target_compile_definitions(phnt INTERFACE
    PHNT_VERSION=PHNT_WINDOWS_11   # Adjust as needed
  )
endif()

if(COLLAT_ENABLE_RPC)
    if(NOT CAPNPROTO_DIR)
        message(WARNING "Path to Cap'n Proto was not provided, RPC server will be disabled! "
        "Please set the `CAPNPROTO_DIR` macro if you wish to enable this feature.")
        unset(COLLAT_ENABLE_RPC)
    else()
        CPMAddPackage(
            NAME capnproto
            SOURCE_DIR ${CAPNPROTO_DIR}
        )
        add_compile_definitions(COLLAT_RPC_ENABLED)
        
        capnp_generate_cpp(COLLAT_RPC_SOURCES COLLAT_RPC_HEADERS src/schema/collat-rpc.capnp)

    endif()
endif()



# Setup Collat project
project(collat VERSION 0.1.0 LANGUAGES C CXX) 

CPMAddPackage(
    "gh:asmjit/asmjit#master"
)

set(COLLAT_SRC
    src/collat.cpp

    src/kernel/kernel.cpp
    include/kernel.hpp
    src/kernel/ioring.cpp
    src/kernel/nt_offsets.cpp
    src/kernel/moduleinfo.cpp
    src/kernel/rop.cpp

    
)

if(COLLAT_ENABLE_RPC)
    set(COLLAT_SRC
        ${COLLAT_SRC}
        src/rpc/implementation.hpp
        src/rpc/server.cpp
    )
endif()


message(NOTICE ${COLLAT_RPC_HEADERS})
add_executable(collat ${COLLAT_SRC} ${COLLAT_RPC_SOURCES})

message(NOTICE ${CMAKE_CURRENT_BINARY_DIR})

target_include_directories(collat PRIVATE "${CMAKE_CURRENT_LIST_DIR}/include" ${CMAKE_CURRENT_BINARY_DIR}/src)
target_compile_definitions(collat PRIVATE UNICODE _UNICODE)

target_link_libraries(collat PRIVATE spdlog::spdlog phnt ntdll onecoreuap)

if(COLLAT_ENABLE_RPC)
    target_link_libraries(collat PRIVATE capnp-rpc $<$<BOOL:${MINGW}>:ws2_32>)
endif()

#target_link_libraries(collat INTERFACE "onecoreuap.lib")