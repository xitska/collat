#include "moduleinfo.h"

#include <Windows.h>
#include <map>
#include <algorithm> 
#include <cctype>
#include <spdlog/spdlog.h>

#include "win_defs.h"
#include "kernel.h"

namespace collat::kmodule {
	std::map<std::string, void*> _module_dictionary;
	std::map<std::string, std::map<std::string, void*>> _export_map;

	std::string to_lower(std::string s) {
		std::transform(s.begin(), s.end(), s._Unchecked_begin(), [](unsigned char c) {
			return std::tolower(c);
		});
		return s;
	}

	int init_module_dictionary() {
		spdlog::debug("grabbing module info: ->");

		ULONG len = 0;
		NTSTATUS status = NtQuerySystemInformation(SystemModuleInformation, NULL, 0, &len);
		if (status != 0xC0000004) {
			spdlog::error("........ failed to grab module info size!");
			return 1;
		}

		PSYSTEM_MODULE_INFORMATION pModuleInfo = (PSYSTEM_MODULE_INFORMATION)malloc(len);
		if (!pModuleInfo) {
			spdlog::error("........ failed to allocate module info!");
			return 2;
		}

		status = NtQuerySystemInformation(SystemModuleInformation, pModuleInfo, len, &len);
		if (status) {
			spdlog::error("........ failed to grab module info!");
			free(pModuleInfo);
			return 3;
		}

		for (size_t i = 0; i < pModuleInfo->NumberOfModules; i++) {
			std::string moduleName = std::string(pModuleInfo->Module[i].ImageName + pModuleInfo->Module[i].ModuleNameOffset);
			moduleName = to_lower(moduleName);

			spdlog::debug("({0:.>27}) @ {1}", moduleName, pModuleInfo->Module[i].Base);

			_module_dictionary.insert({ moduleName, pModuleInfo->Module[i].Base });
		}

		free(pModuleInfo);
		return 0;
	}

	int init_exports_map() {

		spdlog::debug("getting module exports...");

		auto ioring = collat::kernel::get_ioring();

		
		for (auto kv : _module_dictionary) {
			if (kv.first == "dxgkrnl.sys" || kv.first == "dxgmms2.sys" || kv.first == "fs_rec.sys") // skip problematic modules, will fix properly later
				continue;
			spdlog::debug("============================================================");
			//auto pDosHeader = 

			

			spdlog::debug("module: {}", kv.first);
			_export_map.insert({ kv.first, std::map<std::string, void*>()});

			
			uint64_t ullNtHeaders = 0;
			
			uint64_t ullModuleBase = (uint64_t)kv.second;

			if (kv.first == "ntoskrnl.exe")
				ullNtHeaders = collat::kernel::debug_block_decrypt(ullModuleBase, ullModuleBase + 0x38); 
			else 
				ullNtHeaders = ioring->raw_read<uint32_t>((void*)(ullModuleBase + 0x3c)) + ullModuleBase;


			auto pNtHeaders = (PIMAGE_NT_HEADERS)VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			ioring->raw_read_internal((void*)ullNtHeaders,
				pNtHeaders,
				0x1000); // might want to only read to end of page maybbe


			auto pSectionTable = (PIMAGE_SECTION_HEADER)VirtualAlloc(nullptr, pNtHeaders->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			if (!pSectionTable) {
				VirtualFree(pNtHeaders, 0, MEM_DECOMMIT | MEM_RELEASE);
				continue;
			}

			ioring->raw_read_internal((void*)(ullNtHeaders + FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) + pNtHeaders->FileHeader.SizeOfOptionalHeader),
				pSectionTable,
				pNtHeaders->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));



			uint64_t edataAddress = 0;
			uint64_t edataVa = 0;
			size_t edataSize = 0;
			if (pNtHeaders->FileHeader.NumberOfSections) {
				for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
					if (strncmp((const char*)pSectionTable[i].Name, ".edata", 6) == 0 && !(pSectionTable[i].Characteristics & IMAGE_SCN_MEM_DISCARDABLE)) {
						edataAddress = ullModuleBase + pSectionTable[i].VirtualAddress;
						edataVa = pSectionTable[i].VirtualAddress;
						edataSize = pSectionTable[i].Misc.VirtualSize;
						spdlog::debug(".edata: 0x{:x}", edataAddress);
						break;
					}
				}
			}

			if (!edataAddress || !edataVa || !edataSize) {
				//spdlog::warn("no export data for {}, skipping!", kv.first);

				VirtualFree(pSectionTable, 0, MEM_DECOMMIT | MEM_RELEASE);
				VirtualFree(pNtHeaders, 0, MEM_DECOMMIT | MEM_RELEASE);
				continue;
			}

			auto pEdata = VirtualAlloc(nullptr, edataSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			ioring->raw_read_internal((void*)edataAddress, pEdata, edataSize);
			
			if (kv.first == "ntoskrnl.exe") {
				uint64_t* pEdataIt = (uint64_t*)pEdata;
				uint64_t it = 0;
				auto size = (uint32_t)edataSize;
				size >>= 3;
				uint64_t counter = size;
				if (size) {
					do {
						*pEdataIt = collat::kernel::debug_block_decrypt((uint64_t)get_base("ntoskrnl.exe"), edataAddress + it);
						++pEdataIt;
						it += 8;
						--counter;
					} while (counter);
				}
				spdlog::debug("successfully decrypted ntoskrnl export data!");
			}

			

			auto pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)pEdata;

			auto ulNamesOffset = pExportDirectory->AddressOfNames - edataVa;
			auto ulAddressesOffset = pExportDirectory->AddressOfFunctions - edataVa;
			auto ulNameOrdinalOffset = pExportDirectory->AddressOfNameOrdinals - edataVa;

			if (pExportDirectory->NumberOfFunctions) {
				spdlog::debug("parsing export table entries...");
				uint32_t* pulNames = (uint32_t*)((uint64_t)pEdata + ulNamesOffset);
				uint32_t* ppExportAddresses = (uint32_t*)((uint64_t)pEdata + ulAddressesOffset);
				WORD* ppNamesOrdinal = (WORD*)((uint64_t)pEdata + ulNameOrdinalOffset);
				for (size_t i = 0; i < pExportDirectory->NumberOfFunctions; i++) {
					char* exportName = nullptr;
					void* exportAddress = (void*)(ppExportAddresses[i] + ullModuleBase);

					for (size_t j = 0; j < pExportDirectory->NumberOfNames; j++) {
						if (ppNamesOrdinal[j] == i) {
							exportName = (char*)((uint64_t)pEdata + (pulNames[j] - edataVa));
							break;
						}
					}

					if (!exportName)
						continue;

					//spdlog::debug("'{}' @ 0x{:x}", exportName, (uint64_t)exportAddress);
					_export_map.at(kv.first).insert({ std::string(exportName), exportAddress });
				}
				spdlog::debug("successfully parsed all entries!");
			}
			else {
				//spdlog::warn("{} has no exports in edata!", kv.first);
			}


			VirtualFree(pEdata, 0, MEM_DECOMMIT | MEM_RELEASE);
			VirtualFree(pSectionTable, 0, MEM_DECOMMIT | MEM_RELEASE);
			VirtualFree(pNtHeaders, 0, MEM_DECOMMIT | MEM_RELEASE);
		}
		spdlog::debug("============================================================");

		spdlog::debug("finished getting module exports!");

		return 0;
	}

	void* get_export(std::string moduleName, std::string exportName) {
		return _export_map.at(moduleName).at(exportName);
	}

	void* get_base(std::string moduleName) {
		return _module_dictionary.at(to_lower(moduleName));
	}
}