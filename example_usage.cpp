#include <windows.h>
#include <iostream>
#include <fstream>

// toggle whether we use string & include encryption or not.
#define DO_NOT_INCLUDE_STR_CRYPTOR 0 
#include "LibProt.h"


// demo of usage :)
int main()
{
    // ========= required - usage ==========

    uintptr_t AppBaseAddr = LibProt::GetMainAppBase();
    printf("LibProt::GetMainAppBase() returned 0x%p!\r\n\r\n", AppBaseAddr);

    bool SetFakeEntryPointInsideModule = false;
    bool CleanExports = true;
    bool CleanTLSCallbacks = true;

    bool InitValue = LibProt::Initialize(AppBaseAddr, SetFakeEntryPointInsideModule, CleanExports, CleanTLSCallbacks);
    printf("bool InitValue = LibProt::Initialize(0x%p)!\r\n\r\ninitvalue = %d\r\n\r\n", AppBaseAddr, InitValue);

    // ========= optional ==========

    // PAGE_NOACCESS the pe, makes crash on access.
    if (!LibProt::PostInit::PostInitMakePENoAccess(AppBaseAddr))
    {
        printf("LibProt::PostInit::PostInitMakePENoAccess(0x%p) failed!\r\n", AppBaseAddr);
    }


    // PAGE_GUARD the pe, makes crash on access and optionally you can handle hte crash.
    if (!LibProt::PostInit::PostInitMakePEGuarded(AppBaseAddr))
    {
        printf("LibProt::PostInit::PostInitMakePEGuarded(0x%p) failed!\r\n", AppBaseAddr);
    }

    // ========= cool & useeful usage ==========

    printf("calling NtQueryInformationProcess directly w/o asm!\r\n");

    LibProt::Definitions::_PROCESS_BASIC_INFORMATION pbi{};
    ULONG ProcessBasicInformation = 0u;
    size_t returnLength = 0;

    NTSTATUS status = LibProt::Syscaller::CallSyscallSafe<NTSTATUS>(
        "NtQueryInformationProcess", // syscall name :>
        (HANDLE)-1, // current process
        ProcessBasicInformation,
        &pbi,
        sizeof(pbi),
        &returnLength
    );

    if (status == 0) // STATUS_SUCCESS
    {
        printf("peb Address: %p\r\n", pbi.PebBaseAddress);
        printf("CurrentPID: %llu\r\n", (unsigned long long)pbi.UniqueProcessId);
    }
    else
    {
        printf("NtQueryInformationProcess failed with status: 0x%X!!!\r\n", status);
    }

    printf("called NtQueryInformationProcess!\r\n");

    // ========= end  ==========

    printf("done with example usage!!\r\n");

    Sleep(25000); // debug so i can read output, sometimes i don't like to manually cmd.exe call it.

    return 0;
}