#pragma once
#include <string>

namespace collat::kmodule {
	int init_module_dictionary();

	void* get_base(std::string moduleName);
	void* get_export(std::string moduleName, std::string exportName);
	int init_exports_map();
}