#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <Windows.h>
#include <winternl.h>

#define SystemHandleInformation 16

#define EPROC_TOKEN_OFFSET 0x4b8

#define SystemModuleInformation (SYSTEM_INFORMATION_CLASS)0x0b
#define SystemHandleInformation (SYSTEM_INFORMATION_CLASS)16

#define SystemBuildVersionInformation 222

typedef struct _OBJECT_TYPE_INFORMATION
{
    UNICODE_STRING TypeName;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG TotalPagedPoolUsage;
    ULONG TotalNonPagedPoolUsage;
    ULONG TotalNamePoolUsage;
    ULONG TotalHandleTableUsage;
    ULONG HighWaterNumberOfObjects;
    ULONG HighWaterNumberOfHandles;
    ULONG HighWaterPagedPoolUsage;
    ULONG HighWaterNonPagedPoolUsage;
    ULONG HighWaterNamePoolUsage;
    ULONG HighWaterHandleTableUsage;
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccessMask;
    BOOLEAN SecurityRequired;
    BOOLEAN MaintainHandleCount;
    BOOLEAN TypeIndex;
    CHAR ReservedByte;
    ULONG PoolType;
    ULONG DefaultPagedPoolCharge;
    ULONG DefaultNonPagedPoolCharge;
} OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
    unsigned short UniqueProcessId;
    unsigned short CreatorBackTraceIndex;
    unsigned char ObjectTypeIndex;
    unsigned char HandleAttributes;
    unsigned short HandleValue;
    void* Object;
    unsigned long GrantedAccess;
    long __PADDING__[1];
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
    unsigned long NumberOfHandles;
    struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

typedef struct _DISPATCHER_HEADER
{
    union
    {
        volatile long Lock;
        long LockNV;
        struct
        {
            unsigned char Type;
            unsigned char Signalling;
            unsigned char Size;
            unsigned char Reserved1;
        };
        struct
        {
            unsigned char TimerType;
            union
            {
                unsigned char TimerControlFlags;
                struct
                {
                    struct
                    {
                        unsigned char Absolute : 1;
                        unsigned char Wake : 1;
                        unsigned char EncodedTolerableDelay : 6;
                    };
                    unsigned char Hand;
                    union
                    {
                        unsigned char TimerMiscFlags;
                        struct
                        {
                            unsigned char Index : 6;
                            unsigned char Inserted : 1;
                            volatile unsigned char Expired : 1;
                        };
                    };
                };
            };
        };
        struct
        {
            unsigned char Timer2Type;
            union
            {
                unsigned char Timer2Flags;
                struct
                {
                    struct
                    {
                        unsigned char Timer2Inserted : 1;
                        unsigned char Timer2Expiring : 1;
                        unsigned char Timer2CancelPending : 1;
                        unsigned char Timer2SetPending : 1;
                        unsigned char Timer2Running : 1;
                        unsigned char Timer2Disabled : 1;
                        unsigned char Timer2ReservedFlags : 2;
                    };
                    unsigned char Timer2ComponentId;
                    unsigned char Timer2RelativeId;
                };
            };
        };
        struct
        {
            unsigned char QueueType;
            union
            {
                unsigned char QueueControlFlags;
                struct
                {
                    struct
                    {
                        unsigned char Abandoned : 1;
                        unsigned char DisableIncrement : 1;
                        unsigned char QueueReservedControlFlags : 6;
                    };
                    unsigned char QueueSize;
                    unsigned char QueueReserved;
                };
            };
        };
        struct
        {
            unsigned char ThreadType;
            unsigned char ThreadReserved;
            union
            {
                unsigned char ThreadControlFlags;
                struct
                {
                    struct
                    {
                        unsigned char CycleProfiling : 1;
                        unsigned char CounterProfiling : 1;
                        unsigned char GroupScheduling : 1;
                        unsigned char AffinitySet : 1;
                        unsigned char Tagged : 1;
                        unsigned char EnergyProfiling : 1;
                        unsigned char SchedulerAssist : 1;
                        unsigned char ThreadReservedControlFlags : 1;
                    };
                    union
                    {
                        unsigned char DebugActive;
                        struct
                        {
                            unsigned char ActiveDR7 : 1;
                            unsigned char Instrumented : 1;
                            unsigned char Minimal : 1;
                            unsigned char Reserved4 : 2;
                            unsigned char AltSyscall : 1;
                            unsigned char Emulation : 1;
                            unsigned char Reserved5 : 1;
                        };
                    };
                };
            };
        };
        struct
        {
            unsigned char MutantType;
            unsigned char MutantSize;
            unsigned char DpcActive;
            unsigned char MutantReserved;
        };
    };
    long SignalState;
    LIST_ENTRY WaitListHead;
} DISPATCHER_HEADER, * PDISPATCHER_HEADER;

typedef struct _KEVENT
{
    struct _DISPATCHER_HEADER Header;
} KEVENT, * PKEVENT;


//NTSYSCALLAPI NTSTATUS NTAPI NtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);
//NTSYSCALLAPI NTSTATUS NTAPI NtDeviceIoControlFile(HANDLE FileHandle, HANDLE Event, VOID* ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG IoControlCode, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength);
NTSYSCALLAPI NTSTATUS NTAPI NtCreateIoCompletion(PHANDLE IoCompletionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, ULONG NumberOfConcurrentThreads);
NTSYSCALLAPI
NTSTATUS
NTAPI NtSetIoCompletion(HANDLE IoCompletionHandle, ULONG CompletionKey, PIO_STATUS_BLOCK IoStatusBlock, NTSTATUS CompletionStatus, ULONG NumberOfBytesTransferred);

/*NTSYSCALLAPI
NTSTATUS
NTAPI
NtQuerySystemInformation(
    _In_ DWORD SystemInformationClass,
    _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
);*/

NTSYSCALLAPI
NTSTATUS
NTAPI
NtQueryInformationToken(
    _In_ HANDLE TokenHandle,
    _In_ TOKEN_INFORMATION_CLASS TokenInformationClass,
    _Out_writes_bytes_to_opt_(TokenInformationLength, *ReturnLength) PVOID TokenInformation,
    _In_ ULONG TokenInformationLength,
    _Out_ PULONG ReturnLength
);

// Types

#define TOKEN_SECURITY_ATTRIBUTE_TYPE_INVALID 0x00
#define TOKEN_SECURITY_ATTRIBUTE_TYPE_INT64 0x01
#define TOKEN_SECURITY_ATTRIBUTE_TYPE_UINT64 0x02
#define TOKEN_SECURITY_ATTRIBUTE_TYPE_STRING 0x03
#define TOKEN_SECURITY_ATTRIBUTE_TYPE_FQBN 0x04
#define TOKEN_SECURITY_ATTRIBUTE_TYPE_SID 0x05
#define TOKEN_SECURITY_ATTRIBUTE_TYPE_BOOLEAN 0x06
#define TOKEN_SECURITY_ATTRIBUTE_TYPE_OCTET_STRING 0x10

// Flags

#define TOKEN_SECURITY_ATTRIBUTE_NON_INHERITABLE 0x0001
#define TOKEN_SECURITY_ATTRIBUTE_VALUE_CASE_SENSITIVE 0x0002
#define TOKEN_SECURITY_ATTRIBUTE_USE_FOR_DENY_ONLY 0x0004
#define TOKEN_SECURITY_ATTRIBUTE_DISABLED_BY_DEFAULT 0x0008
#define TOKEN_SECURITY_ATTRIBUTE_DISABLED 0x0010
#define TOKEN_SECURITY_ATTRIBUTE_MANDATORY 0x0020
#define TOKEN_SECURITY_ATTRIBUTE_COMPARE_IGNORE 0x0040

#define TOKEN_SECURITY_ATTRIBUTE_VALID_FLAGS ( \
    TOKEN_SECURITY_ATTRIBUTE_NON_INHERITABLE | \
    TOKEN_SECURITY_ATTRIBUTE_VALUE_CASE_SENSITIVE | \
    TOKEN_SECURITY_ATTRIBUTE_USE_FOR_DENY_ONLY | \
    TOKEN_SECURITY_ATTRIBUTE_DISABLED_BY_DEFAULT | \
    TOKEN_SECURITY_ATTRIBUTE_DISABLED | \
    TOKEN_SECURITY_ATTRIBUTE_MANDATORY)

#define TOKEN_SECURITY_ATTRIBUTE_CUSTOM_FLAGS 0xffff0000

// end_rev

// private
typedef struct _TOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE
{
    ULONG64 Version;
    UNICODE_STRING Name;
} TOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE, * PTOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE;

// private
typedef struct _TOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE
{
    PVOID pValue;
    ULONG ValueLength;
} TOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE, * PTOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE;

// private
typedef struct _TOKEN_SECURITY_ATTRIBUTE_V1
{
    UNICODE_STRING Name;
    USHORT ValueType;
    USHORT Reserved;
    ULONG Flags;
    ULONG ValueCount;
    union
    {
        PLONG64 pInt64;
        PULONG64 pUint64;
        PUNICODE_STRING pString;
        PTOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE pFqbn;
        PTOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE pOctetString;
    } Values;
} TOKEN_SECURITY_ATTRIBUTE_V1, * PTOKEN_SECURITY_ATTRIBUTE_V1;

// rev
#define TOKEN_SECURITY_ATTRIBUTES_INFORMATION_VERSION_V1 1
// rev
#define TOKEN_SECURITY_ATTRIBUTES_INFORMATION_VERSION TOKEN_SECURITY_ATTRIBUTES_INFORMATION_VERSION_V1

// private
typedef struct _TOKEN_SECURITY_ATTRIBUTES_INFORMATION
{
    USHORT Version;
    USHORT Reserved;
    ULONG AttributeCount;
    union
    {
        PTOKEN_SECURITY_ATTRIBUTE_V1 pAttributeV1;
    } Attribute;
} TOKEN_SECURITY_ATTRIBUTES_INFORMATION, * PTOKEN_SECURITY_ATTRIBUTES_INFORMATION;

// private
typedef union _SYSTEM_BUILD_VERSION_INFORMATION_FLAGS
{
    ULONG Value32;
    struct
    {
        ULONG IsTopLevel : 1;
        ULONG IsChecked : 1;
    };
} SYSTEM_BUILD_VERSION_INFORMATION_FLAGS, * PSYSTEM_BUILD_VERSION_INFORMATION_FLAGS;

// private
typedef struct _SYSTEM_BUILD_VERSION_INFORMATION
{
    USHORT LayerNumber;
    USHORT LayerCount;
    ULONG OsMajorVersion;
    ULONG OsMinorVersion;
    ULONG NtBuildNumber;
    ULONG NtBuildQfe;
    UCHAR LayerName[128];
    UCHAR NtBuildBranch[128];
    UCHAR NtBuildLab[128];
    UCHAR NtBuildLabEx[128];
    UCHAR NtBuildStamp[26];
    UCHAR NtBuildArch[16];
    SYSTEM_BUILD_VERSION_INFORMATION_FLAGS Flags;
} SYSTEM_BUILD_VERSION_INFORMATION, * PSYSTEM_BUILD_VERSION_INFORMATION;

typedef struct _SYSTEM_MODULE_INFORMATION_ENTRY {
    PVOID  Reserved1;
    PVOID  Reserved2;
    PVOID  Base;
    ULONG  Size;
    ULONG  Flags;
    USHORT Index;
    USHORT Unknown;
    USHORT LoadCount;
    USHORT ModuleNameOffset;
    CHAR   ImageName[256];
} SYSTEM_MODULE_INFORMATION_ENTRY, * PSYSTEM_MODULE_INFORMATION_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION {
    ULONG NumberOfModules;
    SYSTEM_MODULE_INFORMATION_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

typedef struct _NT_IORING_CREATE_FLAGS
{
    enum _NT_IORING_CREATE_REQUIRED_FLAGS Required;
    enum _NT_IORING_CREATE_ADVISORY_FLAGS Advisory;
} NT_IORING_CREATE_FLAGS, * PNT_IORING_CREATE_FLAGS;

typedef struct _NT_IORING_INFO
{
    enum IORING_VERSION IoRingVersion;
    struct _NT_IORING_CREATE_FLAGS Flags;
    unsigned int SubmissionQueueSize;
    unsigned int SubmissionQueueRingMask;
    unsigned int CompletionQueueSize;
    unsigned int CompletionQueueRingMask;
    struct _NT_IORING_SUBMISSION_QUEUE* SubmissionQueue;
    struct _NT_IORING_COMPLETION_QUEUE* CompletionQueue;
} NT_IORING_INFO, * PNT_IORING_INFO;

typedef struct _IOP_MC_BUFFER_ENTRY
{
    USHORT Type;
    USHORT Reserved;
    ULONG Size;
    ULONG ReferenceCount;
    ULONG Flags;
    LIST_ENTRY GlobalDataLink;
    PVOID Address;
    ULONG Length;
    CHAR AccessMode;
    ULONG MdlRef;
    struct _MDL* Mdl;
    KEVENT MdlRundownEvent;
    PULONG64 PfnArray;
    BYTE PageNodes[0x20];
} IOP_MC_BUFFER_ENTRY, * PIOP_MC_BUFFER_ENTRY;

typedef struct _IORING_OBJECT
{
    short Type;
    short Size;
    struct _NT_IORING_INFO UserInfo;
    void* Section;
    struct _NT_IORING_SUBMISSION_QUEUE* SubmissionQueue;
    struct _MDL* CompletionQueueMdl;
    struct _NT_IORING_COMPLETION_QUEUE* CompletionQueue;
    unsigned __int64 ViewSize;
    long InSubmit;
    unsigned __int64 CompletionLock;
    unsigned __int64 SubmitCount;
    unsigned __int64 CompletionCount;
    unsigned __int64 CompletionWaitUntil;
    struct _KEVENT CompletionEvent;
    unsigned char SignalCompletionEvent;
    struct _KEVENT* CompletionUserEvent;
    unsigned int RegBuffersCount;
    struct _IOP_MC_BUFFER_ENTRY** RegBuffers;
    unsigned int RegFilesCount;
    void** RegFiles;
} IORING_OBJECT, * PIORING_OBJECT;

typedef struct _HIORING
{
    HANDLE handle;
    NT_IORING_INFO Info;
    ULONG IoRingKernelAcceptedVersion;
    PVOID RegBufferArray;
    ULONG BufferArraySize;
    PVOID Unknown;
    ULONG FileHandlesCount;
    ULONG SubQueueHead;
    ULONG SubQueueTail;
}_HIORING;

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR  FullPathName[256];

} RTL_PROCESS_MODULE_INFORMATION,
* PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];

} RTL_PROCESS_MODULES,
* PRTL_PROCESS_MODULES;

struct _MMPTE_HARDWARE
{
    ULONGLONG Valid : 1;                                                      //0x0
    ULONGLONG Dirty1 : 1;                                                     //0x0
    ULONGLONG Owner : 1;                                                      //0x0
    ULONGLONG WriteThrough : 1;                                               //0x0
    ULONGLONG CacheDisable : 1;                                               //0x0
    ULONGLONG Accessed : 1;                                                   //0x0
    ULONGLONG Dirty : 1;                                                      //0x0
    ULONGLONG LargePage : 1;                                                  //0x0
    ULONGLONG Global : 1;                                                     //0x0
    ULONGLONG CopyOnWrite : 1;                                                //0x0
    ULONGLONG Unused : 1;                                                     //0x0
    ULONGLONG Write : 1;                                                      //0x0
    ULONGLONG PageFrameNumber : 40;                                           //0x0
    ULONGLONG ReservedForSoftware : 4;                                        //0x0
    ULONGLONG WsleAge : 4;                                                    //0x0
    ULONGLONG WsleProtection : 3;                                             //0x0
    ULONGLONG NoExecute : 1;                                                  //0x0
};

struct _MMPTE_PROTOTYPE
{
    ULONGLONG Valid : 1;                                                      //0x0
    ULONGLONG DemandFillProto : 1;                                            //0x0
    ULONGLONG HiberVerifyConverted : 1;                                       //0x0
    ULONGLONG ReadOnly : 1;                                                   //0x0
    ULONGLONG SwizzleBit : 1;                                                 //0x0
    ULONGLONG Protection : 5;                                                 //0x0
    ULONGLONG Prototype : 1;                                                  //0x0
    ULONGLONG Combined : 1;                                                   //0x0
    ULONGLONG Unused1 : 4;                                                    //0x0
    LONGLONG ProtoAddress : 48;                                               //0x0
};

struct _MMPTE_SOFTWARE
{
    ULONGLONG Valid : 1;                                                      //0x0
    ULONGLONG PageFileReserved : 1;                                           //0x0
    ULONGLONG PageFileAllocated : 1;                                          //0x0
    ULONGLONG ColdPage : 1;                                                   //0x0
    ULONGLONG SwizzleBit : 1;                                                 //0x0
    ULONGLONG Protection : 5;                                                 //0x0
    ULONGLONG Prototype : 1;                                                  //0x0
    ULONGLONG Transition : 1;                                                 //0x0
    ULONGLONG PageFileLow : 4;                                                //0x0
    ULONGLONG UsedPageTableEntries : 10;                                      //0x0
    ULONGLONG ShadowStack : 1;                                                //0x0
    ULONGLONG OnStandbyLookaside : 1;                                         //0x0
    ULONGLONG Unused : 4;                                                     //0x0
    ULONGLONG PageFileHigh : 32;                                              //0x0
};

typedef struct _MMPTE
{
    union
    {
        ULONGLONG Long;                                                     //0x0
        volatile ULONGLONG VolatileLong;                                    //0x0
        struct _MMPTE_HARDWARE Hard;                                        //0x0
        struct _MMPTE_PROTOTYPE Proto;                                      //0x0
        struct _MMPTE_SOFTWARE Soft;                                        //0x0
        /*struct _MMPTE_TIMESTAMP TimeStamp;                                  //0x0
        struct _MMPTE_TRANSITION Trans;                                     //0x0
        struct _MMPTE_SUBSECTION Subsect;                                   //0x0
        struct _MMPTE_LIST List;                                            //0x0*/
    } u;
} MMPTE, * PMMPTE;

NTSYSCALLAPI
NTSTATUS
NTAPI
NtQuerySystemInformationEx(
    _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
    _In_reads_bytes_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
);



#ifdef __cplusplus
}
#endif

