# LibProt
small, 1 header library for protection against dumping tools &amp; pe header, iat, imports/exports protection

# what does this do?
manipulate the pe headers & other fun data dumpers use, along with mess with the peb & ldr

# is this a replacement for (insert virtualization/packer protection)
no. this is meant to compliment such in a form of "antidump"

# why make this?
i got bored + i love fucking with pe headers

# features:
- clear imports, tls callbacks, exports, manipulate pe
- specify whether to destroy tls callbacks
- specify whether to destroy exports
- destruction of real entrypoint (allows customization of whether the entrypoint is set to inside of the module or not)
- allow setting pe header to noaccess/guarded
- rebases your module inside the ldr, dupes ntdll & kernel32.dll to make dumpers have a seizure due to addresses.
- allows calling syscalls directly w/o direct syscall asm or allocation of memory, via swapping the bytes on a useless asm syscall inside ntdll.dll (NtAlpcSendWaitReceivePort), with a return address inside NtAddAtom & ntdll.dll, without modifying return address
- inbuilt xor string encryption (based on [skCryptor](https://github.com/skadro-official/skCrypter) ps: thank you skadro, i use this library an unbelievable amount.)
- custom GetProcAddress impl
- custom GetModuleHandleW impl
- works on dll and exe. (works on x64 (should be easy to add x86 support but admittedly i have no idea)
- lightweight (single header)
- no external dependencies (except windows.h)

# syscall usage:
```cpp

    // ========= syscall ==========

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
```

# enough yap show the difference on why i should use this shit!

## Process Hacker/System Informer having a seizure.
![demonstration libprot](https://github.com/user-attachments/assets/62830265-84c1-414a-979a-125ae30d46e3)

## Scylla resolving ntdll.dll instead of the app
![image](https://github.com/user-attachments/assets/56a5fd5f-cadb-4244-b963-2b5711572fa8)

( i don't use scylla don't flame me )

## this crashes KSDUMPER (the driver causes an immediate bugcheck on refresh)
i don't have proof of this because im lazy to go onto my vm and screenshot but you can test it yourself.

## process dump via https://github.com/glmcdona/Process-Dump fails to resolve the module.
i don't wanna get proof of this because im lazy but you can test it yourself.

## scylla mem dump / ida output completely destroyed
![image](https://github.com/user-attachments/assets/1d5a0a83-ab09-4b7e-9172-1c465b7b0f51)

## ldr showing weird modules & weird ntdll.dll (purple = low image coherency)
![image](https://github.com/user-attachments/assets/dd31f459-da26-4bcc-b7f1-ea98fa8714b6)

# output of the example app 
![image](https://github.com/user-attachments/assets/72a7ffb5-72a6-41a5-97d7-b7782ea99705)
