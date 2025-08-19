# Collat
Collat is a tool for SystemOS kernel-mode code execution and research, based on [Emma Kirkpatrick](https://x.com/carrot_c4k3)'s [Collateral Damage](https://github.com/exploits-forsale/collateral-damage) exploit. Currently it *only* supports OS version 25398.4909 (and 4908?), though can be *somewhat* easily ported to earlier versions.  

If you're interested in how this works, I'm aiming to *potentially* write up a blog post, as the Xbox One kernel appears to have some interesting differences when compared to Windows.  

*Side-note: this project is **not** intended for the end-user, though maybe it can lead to some end-user projects?*

## Usage
To use Collat, you need an existing shell on the Xbox with the ability to run unsigned code. I personally suggest using [AnimaSSH](https://github.com/kwsimons/AnimaSSH) or [Silverton](https://github.com/kwsimons/Silverton) but ultimately you should use whatever suits your workflow and situation.   
*For debug logging, you can pass the `-d` flag on the command line.*

## Building
Collat **only** builds with MSVC, so make sure you have MSVC build tools installed.  
Otherwise, simply build the project like you would any other CMake project:
```bash
git clone -b cmake-v2 git@github.com:xitska/collat.git
cd collat
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

Collat also includes an RPC server, which can be built by providing a path to [Cap'n Proto](https://capnproto.org/), and the `COLLAT_ENABLE_RPC` definition. *See below for an example:*
```bash
git clone -b cmake-v2 git@github.com:xitska/collat.git
cd collat
cmake -S . -B build_rpc -DCMAKE_BUILD_TYPE=Release   \
    -DCAPNPROTO_DIR=E:/repos/capnproto-c++-1.2.0 \ 
    -DCOLLAT_ENABLE_RPC=ON
cmake --build build_rpc
```

### Requirements
- [CMake](https://cmake.org/)
- Windows SDK  >= 10.0.22621.0
- Cap'n Proto (if building RPC server)

## Example code
```cpp
// Calling driver exports (template being return type)
auto partitionId = collat::kernel::call<uint64_t>("xvio.sys", "XvioGetCurrentPartitionId");

// Calling ntoskrnl.exe exports
uint64_t variable = 12;
auto physicalAddress = collat::kernel::call<uint64_t>("ntoskrnl.exe", "MmGetPhysicalAddress", &variable);

// Calling unexported functions
void* functionAddress = collat::kmodule::get_base("ntoskrnl.exe") + 0x13371337;
collat::kernel::call<uint64_t>(functionAddress, 0x10, 0x4, "arg3");

// Reading memory (template being type)
uint64_t data = collat::kernel::get_ioring()->raw_read<uint64_t>(KERNEL_BASE + 0x883322);

auto dosHeader = collat::kernel::get_ioring()->raw_read<IMAGE_DOS_HEADER>(KERNEL_BASE);

// Writing memory (size being derived from template type)
char null[0x10] = { 0 };
collat::kernel::get_ioring()-raw_write<char[0x10]>(ADDRESS, &null);
```

### Advanced example
```cpp
// Creating and executing a ROP chain with multiple functions
void* ApcState;
void* TargetProcess; // Placeholder
size_t BytesTransferred;
NTSTATUS status;
bool result = collat::rop::RopChain()
    .call("ntoskrnl.exe", "KeStackAttachProcess", {TargetProcess, &ApcState}, nullptr)
    .call("ntoskrnl.exe", 
        "MmCopyMemory",
        { // arguments
            0xDEADBEEF,            // TargetAddress
            0xCAFEBABE,            // SourceAddress
            0x1000,                // NumberOfBytes
            MM_COPY_MEMORY_VIRTUAL, // Flags
            &BytesTransferred
        },
        &status
    )
    .call("ntoskrnl.exe", "KeUnstackDetachProcess", {&ApcState})
    .execute();
```

## Contributing
If you're in need of something to do and would like to help, a couple things need to be done:
- [x] Overhaul build system, to simplify building and dependencies
- [ ] Implement the RPC server
- [ ] Allow for dynamic scanning for gadgets in the ROP builder (when using `.gadget("")`)
- [ ] Port to earlier OS versions (namely 4478)
- [ ] Embedding a lightweight interpreter, possibly Lua?

If you'd like any extra information to aid contribution, don't hesitate to get in touch :)

## Thanks
This project would have not been possible without a large number of amazing people and sources, some including:
- [Emma Kirkpatrick](https://x.com/carrot_c4k3) - for the original exploit research, code and help understanding how it works.
- [Cr4sh](https://github.com/Cr4sh/) - for [*KernelForge*](https://github.com/Cr4sh/KernelForge) which acted as inspiration for this project
- [Connor McGarr](https://x.com/33y0re) - for his [*No Code Execution? No Problem!*](https://connormcgarr.github.io/hvci/) blog post
- And everybody in the Xbox One scene!

Overall, I learned a lot, so thanks :)
