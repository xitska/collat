#include "kernel.hpp"
#include "win_defs.h"
#include <phnt_windows.h>
#include <phnt.h>

#include <asmjit/x86.h>

using namespace asmjit;

namespace collat::shellcode
{

    class Assembler : public x86::Assembler
    {
    public:
        Assembler(CodeHolder *code = nullptr) : x86::Assembler(code) {}

        template <typename T>
        inline void call_absolute(T ptr)
        {
            mov(x86::rax, ptr);
            call(x86::rax);
        }
    };

    class Shellcode {
    private:
        Assembler a;
        JitRuntime rt;
        CodeHolder code;

        void* kernel_code_ptr = nullptr;

    private:

        
    public:
        Shellcode() : code(), a(&code) {
            code.init(rt.environment());
        }

        Assembler& assembler() {
            return a;
        }

        void* finalize() {
            void* code_ptr;
            Error err = rt.add(&code_ptr, &code);
            if((uint64_t)code_ptr & 0xfff != 0) {
                spdlog::warn("asmjit code is not aligned, crash is likely!");
            }
            if(err != kErrorOk)
                return nullptr;
            kernel_code_ptr = kernel::map_code_into_kernel(code_ptr, code.code_size());
            return kernel_code_ptr;
        }

        void run() {
            void* ptr = finalize();
            if(kernel_code_ptr != nullptr) {
                collat::kernel::call<uint64_t>(kernel_code_ptr);
            }
        }
    };

    void test_process_callback()
    {
        Shellcode sc;
        auto& a = sc.assembler();
        a.call_absolute(1);
        a.ret();

        sc.finalize();
        
    }

}