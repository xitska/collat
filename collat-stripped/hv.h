#pragma once

#include "kernel.h"

namespace collat::hv {


	// TODO: Use templates to simplify this
	inline uint64_t fast_hypercall(uint32_t CallCode, void* InputData, size_t InputDataSize, void* OutputData, size_t OutputDataSize, uint64_t* RepCount) {
		uint64_t hypercallInputValue = CallCode | 0x10000; // Fast hypercall
		return collat::kernel::call<uint64_t>("ntoskrnl.exe", "HvlFastHypercall", CallCode, InputData, InputDataSize, OutputData, OutputDataSize, RepCount);
	}

	inline uint32_t get_partition_id(void) {
		uint32_t partitionId = -1;
		fast_hypercall(0x28, nullptr, 0, &partitionId, 8, nullptr);
		return partitionId;
	}
}