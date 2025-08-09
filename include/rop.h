#pragma once
#include <vector>
#include <stdint.h>
#include <string>
#include <windows.h>

namespace collat::rop {

    /// @brief Underlying code for executing a ROP chain.
    ///     This can be used to chain together functions that work in pairs (i.e: `KeStackAttachProcess` and `KeUnstackDetachProcess`),
    ///     and will improve performance for larger chains.
    class RopChain {
    private:
        std::vector<uint64_t> _stack;
        std::vector<std::string> _chain_string;

        HANDLE _thread;
        HANDLE _completion_event;

    private:
        RopChain& check_and_align();

    public:
        RopChain();
        ~RopChain();

        RopChain& gadget(std::string gadget);

        template <typename T>
        RopChain& value(T value);

        /// @todo: implement a template/vararg call for ease-of-use?
        RopChain& call(std::string module, std::string name, std::vector<uint64_t> arguments = {}, uint64_t* return_output = nullptr);

        template <typename T>
        RopChain& call(T pointer, std::vector<uint64_t> arguments = {}, uint64_t* return_output = nullptr);

        std::vector<uint64_t> finalize();
        std::vector<std::string> get_chain_string();

        /// @brief Executes the built ROP chain
        /// @param log_stack Whether to debug log the new stack contents
        /// @param timeout How long to wait for execution to complete (in ms)
        /// @return Returns `true` on success, `false` on failure (or timeout)
        bool execute(int timeout = INFINITE, bool log_stack = false);
    };
}