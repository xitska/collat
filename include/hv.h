#pragma once

#include "kernel.hpp"

#define COLLAT_HV_HYPERCALL_LIMIT 0x3d

namespace collat::hv {


	// TODO: Use templates to simplify this
	inline uint64_t fast_hypercall(uint32_t CallCode, const void* InputData, size_t InputDataSize, void* OutputData, size_t OutputDataSize, uint64_t* RepCount) {
		uint64_t hypercallInputValue = CallCode | 0x10000; // Fast hypercall
		return collat::kernel::call<uint64_t>("ntoskrnl.exe", "HvlFastHypercall", CallCode, InputData, InputDataSize, OutputData, OutputDataSize, RepCount);
	}

	inline uint32_t get_partition_id(void) {
		uint32_t partitionId = -1;
		fast_hypercall(0x28, nullptr, 0, &partitionId, 8, nullptr);
		return partitionId;
	}

	inline uint64_t make_data_page_writeable(uint64_t* PhysicalAddress, size_t PhysicalAddressCount, uint64_t* Output, uint64_t OutputSize, uint64_t* RepCount) {
		return fast_hypercall(0x34, (void*)PhysicalAddress, PhysicalAddressCount * 8, (void*)Output, OutputSize, RepCount);
	}

	inline uint64_t make_data_page_readonly(uint64_t* PhysicalAddress, size_t PhysicalAddressCount, uint64_t* Output, uint64_t OutputSize, uint64_t* RepCount) {
		return fast_hypercall(0x32, (void*)PhysicalAddress, PhysicalAddressCount * 8, (void*)Output, OutputSize, RepCount);
	}
}