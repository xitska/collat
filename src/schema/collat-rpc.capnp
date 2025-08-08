@0x8c82f7b41fd65046;

struct ModuleInfo {
    name @0 :Text;
    base @1 :UInt64;
}

interface Collat {
    doFastHypercall @0 (callcode :UInt64, input :Data) -> (repcnt :UInt64, output :Data);

    callKernel @1 (module :Text, function :Text, arguments :List(UInt64)) -> (returnValue :UInt64);
    callKernelAddress @2 (address :UInt64, arguments :List(UInt64)) -> (returnValue :UInt64);

    getKernelModuleBase @3 (moduleName :Text) -> (moduleBase :UInt64);
    getLoadedKernelModules @4 () -> (loadedModules :List(ModuleInfo));

    readKernel @5 (address :UInt64, size :UInt64) -> (data :Data);
    writeKernel @6 (address :UInt64, data :Data);


    createProcess @7 (name :Text, commandLine :Text, flags :UInt32) -> (status :UInt32); 
    startService @8 (service :Text) -> (status :UInt32);

    disableCodeIntegrity @9 (timeout :UInt64);
    restoreCodeIntegrity @10 ();
}