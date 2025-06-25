#include "nt_offsets.h"

#include <Windows.h>

#include "win_defs.h"

namespace collat::nt {
	ULONG build_rev = 0;

	VOID set_build_rev(ULONG rev)
	{
		build_rev = rev;
	}

	UINT64 get_sd_ptr_offset()
	{
		if (build_rev == 4478)
		{
			return SD_PTR_OFFSET_4478;
		}
		else if (build_rev == 4908 || 4909)
		{
			return SD_PTR_OFFSET_4908;
		}

		return 0;
	}

	UINT64 get_orig_sd_offset()
	{
		if (build_rev == 4478)
		{
			return ORIG_SD_OFFSET_4478;
		}
		else if (build_rev == 4908 || 4909)
		{
			return ORIG_SD_OFFSET_4908;
		}

		return 0;
	}

	int get_build_revision() {
		if (!build_rev && build_rev != -1) {
			ULONG ret_len = 0;
			SYSTEM_BUILD_VERSION_INFORMATION build_version = { 0 };
			ULONG layer = 0;
			NtQuerySystemInformationEx((SYSTEM_INFORMATION_CLASS)SystemBuildVersionInformation, &layer, sizeof(layer), &build_version, sizeof(build_version), &ret_len);
			
			build_rev = -1;
			if (build_version.NtBuildNumber == 25398)
				build_rev = build_version.NtBuildQfe;
		}
		
		return build_rev;
	}

	bool build_supported() {
		int revision = get_build_revision();
		if (revision == 4478 || revision == 4908 || revision == 4909)
			return true;
		return false;
	}
}