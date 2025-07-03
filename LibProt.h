#pragma once

#ifndef __LIBPROT_FUNC
#define __LIBPROT_FUNC __forceinline
#endif

// i do not talk about this, heavy thanks to skadro for his skCryptor which i use heavily in my day to day life. 

#if !DO_NOT_INCLUDE_STR_CRYPTOR
namespace LibProt
{


#define TimeConstant2 (__TIME__[4] ^ __DATE__[6] * __LINE__ + __TIME__[2])

#define LP_K1 (char)(((__TIME__[6] ^ __LINE__) + __LINE__ *  __DATE__[7]) % 68 + 87)
#define LP_K2 (char)(((__TIME__[6] ^ __LINE__) + TimeConstant2) % 59 + 16 + __LINE__ *  __DATE__[3])

#define HashTime (__TIME__[2] ^ __DATE__[7] * __DATE__[2] ^ __LINE__ + 5)
#define HashTime2 (__TIME__[5] ^ __DATE__[1] + __DATE__[3] + 9)

    constexpr uint32_t lp_val1 = (__TIME__[7] * 17 + __LINE__ * int(__DATE__[6]) + __DATE__[4] * 8) & 0xFFFF;
    constexpr uint32_t lp_val2 = (__TIME__[5] * 84 + __LINE__ * int(__DATE__[4]) + __DATE__[5] * 6) & 0xFFFF;
    constexpr uint32_t lp_val3 = (__TIME__[6] * 9 + __LINE__ * 9 + __DATE__[5] * 5) & 0xFFFF;
    constexpr uint32_t lp_val4 = (__TIME__[8] * 17 + __LINE__ * 7 + __DATE__[5] * 13) & 0xFFFF;

#define UniqueValue (char)((((__TIME__[6] - '0') * lp_val1) + ((__TIME__[6] - '0') * int(HashTime2)) + ((__TIME__[4] - '0') * 25) + (__TIME__[5] - '0') % HashTime2) % lp_val3)
#define UniqueValueSmall (char)(((__TIME__[7] - '0') % lp_val1) + lp_val4)

    namespace LPCryption
    {
        namespace __std
        {
            template <class _Ty> struct remove_reference { using type = _Ty; };
            template <class _Ty> struct remove_reference<_Ty&> { using type = _Ty; };
            template <class _Ty> struct remove_reference<_Ty&&> { using type = _Ty; };
            template <class _Ty> using remove_reference_t = typename remove_reference<_Ty>::type;

            template <class _Ty> struct remove_const { using type = _Ty; };
            template <class _Ty> struct remove_const<const _Ty> { using type = _Ty; };
            template <class _Ty> using remove_const_t = typename remove_const<_Ty>::type;
        }




        template<class _Ty>
        using clean_type = typename __std::remove_const_t<__std::remove_reference_t<_Ty>>;

        constexpr uint32_t lp_val_rand = (__TIME__[5] * HashTime + __LINE__ * 7 + lp_val2 * 3) * (UniqueValue * UniqueValueSmall);
        constexpr uint32_t lp_val_rand_2 = ((lp_val_rand / lp_val4) + TimeConstant2 / lp_val1) + UniqueValue;

        constexpr uint32_t lcg(uint32_t seed, int rounds = 5)
        {
            for (int i = 0; i < rounds; ++i)
                seed = 1664525u * seed + 1013904223u;
            return seed;
        }

        template <int _size, char _key1, char _key2, typename T>
        class LPCrypt
        {
        public:
            __forceinline constexpr LPCrypt(const T* data)
            {
                encrypt(data);
            }

            __forceinline T* get() { return _storage; }

            __forceinline int size() const { return _size; }

            __forceinline char key1() const { return _key1; }
            __forceinline char key2() const { return _key2; }

            __forceinline T* decrypt()
            {
                if (_encrypted)
                {
                    transform();
                    _encrypted = false;
                }
                return _storage;
            }

            __forceinline void clear()
            {
                for (int i = 0; i < _size; i++) _storage[i] = 0;
            }

            __forceinline operator T* ()
            {
                decrypt();
                return _storage;
            }

        private:
            mutable bool _encrypted = true;
            T _storage[_size]{};

            __forceinline constexpr void encrypt(const T* data)
            {
                for (int i = 0; i < _size; ++i)
                {
                    uint32_t noise = lcg(lp_val_rand + i, 5);
                    _storage[_size - i - 1] = data[i] ^ (_key1 + (i % (_key2 + 2)) + (char)(noise % 8));
                }
            }

            __forceinline void transform()
            {
                for (int i = 0; i < _size; ++i)
                {
                    uint32_t noise = lcg(lp_val_rand + (_size - i - 1), 5);
                    T tmp = _storage[i] ^ (_key1 + ((_size - i - 1) % (_key2 + 2)) + (char)(noise % 8));
                    _storage[i] = tmp;
                }
                reverse();
            }

            __forceinline void reverse()
            {
                for (int i = 0; i < _size / 2; ++i)
                {
                    T temp = _storage[i];
                    _storage[i] = _storage[_size - i - 1];
                    _storage[_size - i - 1] = temp;
                }
            }
        };
    }

    // main encryption func
#define LPCrypt_key(str, key1, key2) []() { \
			constexpr static auto crypted = LPCryption::LPCrypt \
				<sizeof(str) / sizeof(str[0]), key1, key2, LPCryption::clean_type<decltype(str[0])>>((LPCryption::clean_type<decltype(str[0])>*)str); \
					return crypted; }()


// different encryption than encrypt1
#define Encrypt2(str) LPCrypt_key(str, UniqueValue, LP_K1)

// main encryption.
#define Encrypt(str) LPCrypt_key(str, LP_K1, UniqueValueSmall)
}
#endif


namespace LibProt
{

    namespace Definitions
    {

        typedef struct _UNICODE_STRING {
            USHORT Length;
            USHORT MaximumLength;
            PWSTR  Buffer;
        } UNICODE_STRING, * PUNICODE_STRING;
        typedef const UNICODE_STRING* PCUNICODE_STRING;

#define GDI_HANDLE_BUFFER_SIZE32  34
#define GDI_HANDLE_BUFFER_SIZE64  60

#if !defined(_M_X64)
#define GDI_HANDLE_BUFFER_SIZE      GDI_HANDLE_BUFFER_SIZE32
#else
#define GDI_HANDLE_BUFFER_SIZE      GDI_HANDLE_BUFFER_SIZE64
#endif

        typedef ULONG GDI_HANDLE_BUFFER32[GDI_HANDLE_BUFFER_SIZE32];
        typedef ULONG GDI_HANDLE_BUFFER64[GDI_HANDLE_BUFFER_SIZE64];
        typedef ULONG GDI_HANDLE_BUFFER[GDI_HANDLE_BUFFER_SIZE];


        typedef struct _STRING {
            USHORT Length;
            USHORT MaximumLength;
            PCHAR Buffer;
        } STRING;
        typedef STRING* PSTRING;

        typedef STRING ANSI_STRING;
        typedef PSTRING PANSI_STRING;

        typedef STRING OEM_STRING;
        typedef PSTRING POEM_STRING;
        typedef CONST STRING* PCOEM_STRING;
        typedef CONST char* PCSZ;

        typedef struct _RTL_DRIVE_LETTER_CURDIR {
            USHORT Flags;
            USHORT Length;
            ULONG TimeStamp;
            STRING DosPath;
        } RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;

#define RTL_MAX_DRIVE_LETTERS 32
#define RTL_DRIVE_LETTER_VALID (USHORT)0x0001

        // 32-bit definitions
        typedef struct _STRING32 {
            USHORT Length;
            USHORT MaximumLength;
            ULONG Buffer;
        } STRING32;
        typedef STRING32* PSTRING32;

        typedef STRING32 UNICODE_STRING32;

#if (_MSC_VER < 1300) && !defined(_WINDOWS_)
        typedef struct LIST_ENTRY32 {
            DWORD Flink;
            DWORD Blink;
        } LIST_ENTRY32;
        typedef LIST_ENTRY32* PLIST_ENTRY32;

        typedef struct LIST_ENTRY64 {
            ULONGLONG Flink;
            ULONGLONG Blink;
        } LIST_ENTRY64;
        typedef LIST_ENTRY64* PLIST_ENTRY64;
#endif

#define WOW64_POINTER(Type) ULONG

        typedef struct _PEB_LDR_DATA32 {
            ULONG Length;
            BOOLEAN Initialized;
            WOW64_POINTER(HANDLE) SsHandle;
            LIST_ENTRY32 InLoadOrderModuleList;
            LIST_ENTRY32 InMemoryOrderModuleList;
            LIST_ENTRY32 InInitializationOrderModuleList;
            WOW64_POINTER(PVOID) EntryInProgress;
            BOOLEAN ShutdownInProgress;
            WOW64_POINTER(HANDLE) ShutdownThreadId;
        } PEB_LDR_DATA32, * PPEB_LDR_DATA32;

#define LDR_DATA_TABLE_ENTRY_SIZE_WINXP32 FIELD_OFFSET( LDR_DATA_TABLE_ENTRY32, ForwarderLinks )

        typedef struct _LDR_DATA_TABLE_ENTRY32 {
            LIST_ENTRY32 InLoadOrderLinks;
            LIST_ENTRY32 InMemoryOrderLinks;
            LIST_ENTRY32 InInitializationOrderLinks;
            WOW64_POINTER(PVOID) DllBase;
            WOW64_POINTER(PVOID) EntryPoint;
            ULONG SizeOfImage;
            UNICODE_STRING32 FullDllName;
            UNICODE_STRING32 BaseDllName;
            ULONG Flags;
            USHORT LoadCount;
            USHORT TlsIndex;
            union
            {
                LIST_ENTRY32 HashLinks;
                struct
                {
                    WOW64_POINTER(PVOID) SectionPointer;
                    ULONG CheckSum;
                };
            };
            union
            {
                ULONG TimeDateStamp;
                WOW64_POINTER(PVOID) LoadedImports;
            };
            WOW64_POINTER(PVOID) EntryPointActivationContext;
            WOW64_POINTER(PVOID) PatchInformation;
            LIST_ENTRY32 ForwarderLinks;
            LIST_ENTRY32 ServiceTagLinks;
            LIST_ENTRY32 StaticLinks;
            WOW64_POINTER(PVOID) ContextInformation;
            WOW64_POINTER(ULONG_PTR) OriginalBase;
            LARGE_INTEGER LoadTime;
        } LDR_DATA_TABLE_ENTRY32, * PLDR_DATA_TABLE_ENTRY32;

        typedef struct _ACTIVATION_CONTEXT_DATA* PACTIVATION_CONTEXT_DATA;
        typedef struct _ASSEMBLY_STORAGE_MAP* PASSEMBLY_STORAGE_MAP;

        typedef struct _PEB_LDR_DATA {
            ULONG Length;
            BOOLEAN Initialized;
            HANDLE SsHandle;
            LIST_ENTRY InLoadOrderModuleList;
            LIST_ENTRY InMemoryOrderModuleList;
            LIST_ENTRY InInitializationOrderModuleList;
            PVOID EntryInProgress;
            BOOLEAN ShutdownInProgress;
            HANDLE ShutdownThreadId;
        } PEB_LDR_DATA, * PPEB_LDR_DATA;



        typedef struct _CURDIR {
            UNICODE_STRING DosPath;
            HANDLE Handle;
        } CURDIR, * PCURDIR;


        typedef struct _RTL_DRIVE_LETTER_CURDIR32 {
            USHORT Flags;
            USHORT Length;
            ULONG TimeStamp;
            STRING32 DosPath;
        } RTL_DRIVE_LETTER_CURDIR32, * PRTL_DRIVE_LETTER_CURDIR32;

        typedef struct _RTL_USER_PROCESS_PARAMETERS {
            ULONG MaximumLength;
            ULONG Length;

            ULONG Flags;
            ULONG DebugFlags;

            HANDLE ConsoleHandle;
            ULONG ConsoleFlags;
            HANDLE StandardInput;
            HANDLE StandardOutput;
            HANDLE StandardError;

            CURDIR CurrentDirectory;
            UNICODE_STRING DllPath;
            UNICODE_STRING ImagePathName;
            UNICODE_STRING CommandLine;
            PVOID Environment;

            ULONG StartingX;
            ULONG StartingY;
            ULONG CountX;
            ULONG CountY;
            ULONG CountCharsX;
            ULONG CountCharsY;
            ULONG FillAttribute;

            ULONG WindowFlags;
            ULONG ShowWindowFlags;
            UNICODE_STRING WindowTitle;
            UNICODE_STRING DesktopInfo;
            UNICODE_STRING ShellInfo;
            UNICODE_STRING RuntimeData;
            RTL_DRIVE_LETTER_CURDIR CurrentDirectories[RTL_MAX_DRIVE_LETTERS];

            ULONG_PTR EnvironmentSize;
            ULONG_PTR EnvironmentVersion;

            PVOID PackageDependencyData;
            ULONG ProcessGroupId;
            ULONG LoaderThreads;

            UNICODE_STRING RedirectionDllName; // RS4
            UNICODE_STRING HeapPartitionName; // 19H1
            ULONG_PTR DefaultThreadpoolCpuSetMasks;
            ULONG DefaultThreadpoolCpuSetMaskCount;
            ULONG DefaultThreadpoolThreadMaximum;
            ULONG HeapMemoryTypeMask; // WIN11
        } RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

        typedef struct _PEB {
            BOOLEAN InheritedAddressSpace;
            BOOLEAN ReadImageFileExecOptions;
            BOOLEAN BeingDebugged;
            union
            {
                BOOLEAN BitField;
                struct
                {
                    BOOLEAN ImageUsesLargePages : 1;
                    BOOLEAN IsProtectedProcess : 1;
                    BOOLEAN IsImageDynamicallyRelocated : 1;
                    BOOLEAN SkipPatchingUser32Forwarders : 1;
                    BOOLEAN IsPackagedProcess : 1;
                    BOOLEAN IsAppContainer : 1;
                    BOOLEAN IsProtectedProcessLight : 1;
                    BOOLEAN IsLongPathAwareProcess : 1;
                };
            };

            HANDLE Mutant;

            PVOID ImageBaseAddress;
            PPEB_LDR_DATA Ldr;
            PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
            PVOID SubSystemData;
            PVOID ProcessHeap;
            PRTL_CRITICAL_SECTION FastPebLock;
            PSLIST_HEADER AtlThunkSListPtr;
            PVOID IFEOKey;

            union
            {
                ULONG CrossProcessFlags;
                struct
                {
                    ULONG ProcessInJob : 1;
                    ULONG ProcessInitializing : 1;
                    ULONG ProcessUsingVEH : 1;
                    ULONG ProcessUsingVCH : 1;
                    ULONG ProcessUsingFTH : 1;
                    ULONG ProcessPreviouslyThrottled : 1;
                    ULONG ProcessCurrentlyThrottled : 1;
                    ULONG ProcessImagesHotPatched : 1; // RS5
                    ULONG ReservedBits0 : 24;
                };
            };
            union
            {
                PVOID KernelCallbackTable;
                PVOID UserSharedInfoPtr;
            };
            ULONG SystemReserved;
            ULONG AtlThunkSListPtr32;
            PVOID ApiSetMap;
            ULONG TlsExpansionCounter;
            PVOID TlsBitmap;
            ULONG TlsBitmapBits[2];

            PVOID ReadOnlySharedMemoryBase;
            struct _SILO_USER_SHARED_DATA* SharedData;
            PVOID* ReadOnlyStaticServerData;

            PVOID AnsiCodePageData;
            PVOID OemCodePageData;
            PVOID UnicodeCaseTableData;

            ULONG NumberOfProcessors;
            ULONG NtGlobalFlag;

            ULARGE_INTEGER CriticalSectionTimeout;
            SIZE_T HeapSegmentReserve;
            SIZE_T HeapSegmentCommit;
            SIZE_T HeapDeCommitTotalFreeThreshold;
            SIZE_T HeapDeCommitFreeBlockThreshold;

            ULONG NumberOfHeaps;
            ULONG MaximumNumberOfHeaps;
            PVOID* ProcessHeaps;

            PVOID GdiSharedHandleTable;
            PVOID ProcessStarterHelper;
            ULONG GdiDCAttributeList;

            PRTL_CRITICAL_SECTION LoaderLock;

            ULONG OSMajorVersion;
            ULONG OSMinorVersion;
            USHORT OSBuildNumber;
            USHORT OSCSDVersion;
            ULONG OSPlatformId;
            ULONG ImageSubsystem;
            ULONG ImageSubsystemMajorVersion;
            ULONG ImageSubsystemMinorVersion;
            KAFFINITY ActiveProcessAffinityMask;
            GDI_HANDLE_BUFFER GdiHandleBuffer;
            PVOID PostProcessInitRoutine;

            PVOID TlsExpansionBitmap;
            ULONG TlsExpansionBitmapBits[32];

            ULONG SessionId;

            ULARGE_INTEGER AppCompatFlags;
            ULARGE_INTEGER AppCompatFlagsUser;
            PVOID pShimData;
            PVOID AppCompatInfo;

            UNICODE_STRING CSDVersion;

            PACTIVATION_CONTEXT_DATA ActivationContextData;
            PASSEMBLY_STORAGE_MAP ProcessAssemblyStorageMap;
            PACTIVATION_CONTEXT_DATA SystemDefaultActivationContextData;
            PASSEMBLY_STORAGE_MAP SystemAssemblyStorageMap;

            SIZE_T MinimumStackCommit;

            PVOID SparePointers[2];
            PVOID PatchLoaderData;
            PVOID ChpeV2ProcessInfo;

            ULONG AppModelFeatureState;
            ULONG SpareUlongs[2];

            USHORT ActiveCodePage;
            USHORT OemCodePage;
            USHORT UseCaseMapping;
            USHORT UnusedNlsField;

            PVOID WerRegistrationData;
            PVOID WerShipAssertPtr;

            union
            {
                PVOID pContextData;
                PVOID pUnused;
                PVOID EcCodeBitMap;
            };

            PVOID pImageHeaderHash;
            union
            {
                ULONG TracingFlags;
                struct
                {
                    ULONG HeapTracingEnabled : 1;
                    ULONG CritSecTracingEnabled : 1;
                    ULONG LibLoaderTracingEnabled : 1;
                    ULONG SpareTracingBits : 29;
                };
            };
            ULONGLONG CsrServerReadOnlySharedMemoryBase;
            PRTL_CRITICAL_SECTION TppWorkerpListLock;
            LIST_ENTRY TppWorkerpList;
            PVOID WaitOnAddressHashTable[128];
            PVOID TelemetryCoverageHeader; // RS3
            ULONG CloudFileFlags;
            ULONG CloudFileDiagFlags; // RS4
            CHAR PlaceholderCompatibilityMode;
            CHAR PlaceholderCompatibilityModeReserved[7];
            struct _LEAP_SECOND_DATA* LeapSecondData; // RS5
            union
            {
                ULONG LeapSecondFlags;
                struct
                {
                    ULONG SixtySecondEnabled : 1;
                    ULONG Reserved : 31;
                };
            };
            ULONG NtGlobalFlag2;
            ULONGLONG ExtendedFeatureDisableMask; // since WIN11
        } PEB, * PPEB;


        typedef struct _LDR_RESOURCE_INFO {
            ULONG_PTR Type;
            ULONG_PTR Name;
            ULONG Lang;
        } LDR_RESOURCE_INFO, * PLDR_RESOURCE_INFO;

        typedef struct _LDR_DATA_TABLE_ENTRY_COMPATIBLE {
            LIST_ENTRY InLoadOrderLinks;
            LIST_ENTRY InMemoryOrderLinks;
            union
            {
                LIST_ENTRY InInitializationOrderLinks;
                LIST_ENTRY InProgressLinks;
            } DUMMYUNION0;
            PVOID DllBase;
            PVOID EntryPoint;
            ULONG SizeOfImage;
            UNICODE_STRING FullDllName;
            UNICODE_STRING BaseDllName;
            union
            {
                ULONG Flags;
                struct
                {
                    ULONG PackagedBinary : 1; // Size=4 Offset=104 BitOffset=0 BitCount=1
                    ULONG MarkedForRemoval : 1; // Size=4 Offset=104 BitOffset=1 BitCount=1
                    ULONG ImageDll : 1; // Size=4 Offset=104 BitOffset=2 BitCount=1
                    ULONG LoadNotificationsSent : 1; // Size=4 Offset=104 BitOffset=3 BitCount=1
                    ULONG TelemetryEntryProcessed : 1; // Size=4 Offset=104 BitOffset=4 BitCount=1
                    ULONG ProcessStaticImport : 1; // Size=4 Offset=104 BitOffset=5 BitCount=1
                    ULONG InLegacyLists : 1; // Size=4 Offset=104 BitOffset=6 BitCount=1
                    ULONG InIndexes : 1; // Size=4 Offset=104 BitOffset=7 BitCount=1
                    ULONG ShimDll : 1; // Size=4 Offset=104 BitOffset=8 BitCount=1
                    ULONG InExceptionTable : 1; // Size=4 Offset=104 BitOffset=9 BitCount=1
                    ULONG ReservedFlags1 : 2; // Size=4 Offset=104 BitOffset=10 BitCount=2
                    ULONG LoadInProgress : 1; // Size=4 Offset=104 BitOffset=12 BitCount=1
                    ULONG LoadConfigProcessed : 1; // Size=4 Offset=104 BitOffset=13 BitCount=1
                    ULONG EntryProcessed : 1; // Size=4 Offset=104 BitOffset=14 BitCount=1
                    ULONG ProtectDelayLoad : 1; // Size=4 Offset=104 BitOffset=15 BitCount=1
                    ULONG ReservedFlags3 : 2; // Size=4 Offset=104 BitOffset=16 BitCount=2
                    ULONG DontCallForThreads : 1; // Size=4 Offset=104 BitOffset=18 BitCount=1
                    ULONG ProcessAttachCalled : 1; // Size=4 Offset=104 BitOffset=19 BitCount=1
                    ULONG ProcessAttachFailed : 1; // Size=4 Offset=104 BitOffset=20 BitCount=1
                    ULONG CorDeferredValidate : 1; // Size=4 Offset=104 BitOffset=21 BitCount=1
                    ULONG CorImage : 1; // Size=4 Offset=104 BitOffset=22 BitCount=1
                    ULONG DontRelocate : 1; // Size=4 Offset=104 BitOffset=23 BitCount=1
                    ULONG CorILOnly : 1; // Size=4 Offset=104 BitOffset=24 BitCount=1
                    ULONG ChpeImage : 1; // Size=4 Offset=104 BitOffset=25 BitCount=1
                    ULONG ReservedFlags5 : 2; // Size=4 Offset=104 BitOffset=26 BitCount=2
                    ULONG Redirected : 1; // Size=4 Offset=104 BitOffset=28 BitCount=1
                    ULONG ReservedFlags6 : 2; // Size=4 Offset=104 BitOffset=29 BitCount=2
                    ULONG CompatDatabaseProcessed : 1; // Size=4 Offset=104 BitOffset=31 BitCount=1
                };
            } ENTRYFLAGSUNION;
            WORD ObsoleteLoadCount;
            WORD TlsIndex;
            union
            {
                LIST_ENTRY HashLinks;
                struct
                {
                    PVOID SectionPointer;
                    ULONG CheckSum;
                };
            } DUMMYUNION1;
            union
            {
                ULONG TimeDateStamp;
                PVOID LoadedImports;
            } DUMMYUNION2;
            //fields below removed for compatibility, if you need them use LDR_DATA_TABLE_ENTRY_FULL
        } LDR_DATA_TABLE_ENTRY_COMPATIBLE, * PLDR_DATA_TABLE_ENTRY_COMPATIBLE;
        typedef LDR_DATA_TABLE_ENTRY_COMPATIBLE LDR_DATA_TABLE_ENTRY;
        typedef LDR_DATA_TABLE_ENTRY_COMPATIBLE* PLDR_DATA_TABLE_ENTRY;
        typedef LDR_DATA_TABLE_ENTRY* PCLDR_DATA_TABLE_ENTRY;


        // Define the PROCESS_BASIC_INFORMATION structure
        typedef struct _PROCESS_BASIC_INFORMATION {
            PVOID Reserved1;
            LibProt::Definitions::PEB* PebBaseAddress;
            PVOID Reserved2[2];
            ULONG_PTR UniqueProcessId;
            PVOID Reserved3;
        } PROCESS_BASIC_INFORMATION;

    }

    namespace Internals
    {
        __LIBPROT_FUNC void* __memset(void* dst0, int c0, unsigned int len)
        {
            unsigned int i;
            unsigned int fill;
            unsigned int chunks = len / sizeof(fill);
            char* char_dest = (char*)dst0;
            unsigned int* uint_dest = (unsigned int*)dst0;
            fill = (c0 << 24) + (c0 << 16) + (c0 << 8) + c0;

            for (i = len; i > chunks * sizeof(fill); i--)
            {
                char_dest[i - 1] = c0;
            }

            for (i = chunks; i > 0; i--)
            {
                uint_dest[i - 1] = fill;
            }

            return dst0;
        }

        __LIBPROT_FUNC void* __memcpy(void* dest, const void* src, unsigned long long count)
        {
            char* char_dest = (char*)dest;
            char* char_src = (char*)src;
            if ((char_dest <= char_src) || (char_dest >= (char_src + count)))
            {
                while (count > 0)
                {
                    *char_dest = *char_src;
                    char_dest++;
                    char_src++;
                    count--;
                }
            }
            else
            {
                char_dest = (char*)dest + count - 1;
                char_src = (char*)src + count - 1;
                while (count > 0)
                {
                    *char_dest = *char_src;
                    char_dest--;
                    char_src--;
                    count--;
                }
            }

            return dest;
        }


        __LIBPROT_FUNC LibProt::Definitions::PEB* GetPEB() noexcept
        {
            return reinterpret_cast<LibProt::Definitions::PEB*>(__readgsqword(0x60));
        }


        __LIBPROT_FUNC uintptr_t GetModuleHandleWSafe(const wchar_t* ModuleName)
        {
            LibProt::Definitions::PEB* Peb = reinterpret_cast<LibProt::Definitions::PEB*>(LibProt::Internals::GetPEB());

            LibProt::Definitions::PPEB_LDR_DATA PebLdr = Peb->Ldr;
            LIST_ENTRY* Head = &PebLdr->InLoadOrderModuleList;
            LIST_ENTRY* Current = Head->Flink;

            while (Current && Current != Head)
            {
                auto entry = CONTAINING_RECORD(Current, LibProt::Definitions::LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

                if (entry->BaseDllName.Buffer && _wcsicmp(entry->BaseDllName.Buffer, ModuleName) == 0)
                {
                    return reinterpret_cast<uintptr_t>(entry->DllBase);
                }

                Current = Current->Flink;
            }

            return 0;
        }

        __LIBPROT_FUNC uintptr_t GetProcAddressByBase(uintptr_t ModuleBase, const char* FunctionName)
        {
            auto ModuleAddress = ModuleBase; // this looks better
            if (!ModuleAddress) return 0;

            IMAGE_DOS_HEADER* DosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(ModuleAddress);
            if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE) return 0;

            IMAGE_NT_HEADERS64* NtHeader = reinterpret_cast<IMAGE_NT_HEADERS64*>(reinterpret_cast<uint8_t*>(ModuleAddress) + DosHeader->e_lfanew);
            if (NtHeader->Signature != IMAGE_NT_SIGNATURE) return 0;

            auto ImageExportVa = NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            if (!ImageExportVa) return 0;

            IMAGE_EXPORT_DIRECTORY* ImageExportDir = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(reinterpret_cast<uint8_t*>(ModuleAddress) + ImageExportVa);

            auto AddressOfFunctions = reinterpret_cast<uint32_t*>(reinterpret_cast<uint8_t*>(ModuleAddress) + ImageExportDir->AddressOfFunctions);
            auto AddressOfNames = reinterpret_cast<uint32_t*>(reinterpret_cast<uint8_t*>(ModuleAddress) + ImageExportDir->AddressOfNames);
            auto AddressOfNameOrdinals = reinterpret_cast<uint16_t*>(reinterpret_cast<uint8_t*>(ModuleAddress) + ImageExportDir->AddressOfNameOrdinals);

            for (auto i = 0; i < ImageExportDir->NumberOfNames; i++)
            {
                auto StringMatches = false;
                char* CurrentName = reinterpret_cast<char*>(ModuleAddress) + AddressOfNames[i];

                for (auto i = 0;; i++)
                {
                    if (CurrentName[i] == '\0' || FunctionName[i] == '\0')
                    {
                        break;
                    }
                    else
                    {
                        if (CurrentName[i] == FunctionName[i])
                        {
                            StringMatches = true;
                            continue;
                        }
                        else
                        {
                            StringMatches = false;
                            break;
                        }
                    }
                }

                if (StringMatches)
                {
                    return reinterpret_cast<uintptr_t>((uint8_t*)ModuleAddress + AddressOfFunctions[AddressOfNameOrdinals[i]]);
                }
            }

            return 0;
        }

        __LIBPROT_FUNC uintptr_t GetProcAddressByName(const wchar_t* ModuleName, const char* FunctionName)
        {
            auto ModuleAddress = LibProt::Internals::GetModuleHandleWSafe(ModuleName);
            if (!ModuleAddress) return 0;

            return LibProt::Internals::GetProcAddressByBase(ModuleAddress, FunctionName);
        }


        // gets cached addr
        __LIBPROT_FUNC uintptr_t GetNTDllBaseAddress()
        {
            static uintptr_t NtDllBase = 0;

#if !DO_NOT_INCLUDE_STR_CRYPTOR
            if (!NtDllBase)
                NtDllBase = LibProt::Internals::GetModuleHandleWSafe(Encrypt(L"ntdll.dll").decrypt());
#else
            if (!NtDllBase)
                NtDllBase = LibProt::Internals::GetModuleHandleWSafe(L"ntdll.dll");
#endif
            return NtDllBase;
        }

        // this returns NtAlpcSendWaitReceivePort rn, you can change thouigh.
        __LIBPROT_FUNC uintptr_t GetTargetSyscallHookAddr()
        {
            uintptr_t NtDllBase = LibProt::Internals::GetNTDllBaseAddress();
            if (!NtDllBase) return 0;

#if !DO_NOT_INCLUDE_STR_CRYPTOR
            uintptr_t syscallStubAddr = LibProt::Internals::GetProcAddressByBase(NtDllBase, Encrypt("NtAlpcSendWaitReceivePort").decrypt()); // .decrypt() because im used to it ngl
#else
            uintptr_t syscallStubAddr = LibProt::Internals::GetProcAddressByBase(NtDllBase, "NtAlpcSendWaitReceivePort");
#endif

            return syscallStubAddr;
        }
    }

    // copies kernel32.dll pe header to our own. :3
    __LIBPROT_FUNC void CopyKernel32Header(void* LocalModule)
    {
        // TODO: maybe dynamically resolve syscalls?
#if !DO_NOT_INCLUDE_STR_CRYPTOR
        uintptr_t Kernel32Base = LibProt::Internals::GetModuleHandleWSafe(Encrypt(L"Kernel32.dll").decrypt());
#else
        uintptr_t Kernel32Base = LibProt::Internals::GetModuleHandleWSafe(L"Kernel32.dll");
#endif
        if (!Kernel32Base) return; // failed to resolve.

        DWORD OldProtection = 0;

        // some shit detects 0x1000 (4096) as the sizeof pe and thus detects/prevents pe manipualtion, usually the last is padding anyways, 0xFFF = 4095 so good enough to skip a byte or two.
        if (VirtualProtect(LocalModule, 0xFFF, PAGE_EXECUTE_READWRITE, &OldProtection))
        {
            LibProt::Internals::__memcpy(LocalModule, reinterpret_cast<void*>(Kernel32Base), 0xFFF); // copy pe from, kernel32.dll to our mem :>
        }

        VirtualProtect(LocalModule, 0xFFF, OldProtection, &OldProtection); // restore the prot
    }

    // gets syscall idx
    __LIBPROT_FUNC uint32_t GetSyscallIDX(const wchar_t* ModuleName, const char* FunctionName)
    {
        auto FuncAddr = LibProt::Internals::GetProcAddressByName(ModuleName, FunctionName);
        if (!FuncAddr) return 0;

        return *(uint32_t*)((FuncAddr + 4));
    }

    // gets syscall idx, uses base rather than luh module name
    __LIBPROT_FUNC uint32_t GetSyscallIDX(uintptr_t TargetModuleBase, const char* FunctionName)
    {
        auto FuncAddr = LibProt::Internals::GetProcAddressByBase(TargetModuleBase, FunctionName);
        if (!FuncAddr) return 0;

        return *(uint32_t*)((FuncAddr + 4));
    }

    // gets syscall idx, uses base rather than luh module name (uses ptr ver)
    __LIBPROT_FUNC uint32_t GetSyscallIDX(void* TargetModuleBase, const char* FunctionName) { return GetSyscallIDX(reinterpret_cast<uintptr_t>(TargetModuleBase), FunctionName); };

    // allows setting syscall data
    __LIBPROT_FUNC bool OverwriteSyscall(uint32_t NewSyscallIDX, PDWORD OldProtectionOut, uint32_t* OriginalSyscallIDX, DWORD NewProtection = PAGE_EXECUTE_READWRITE)
    {
        uintptr_t NtDllBase = LibProt::Internals::GetNTDllBaseAddress();
        uintptr_t NtAlpcSendWaitReceivePortAddr = LibProt::Internals::GetTargetSyscallHookAddr();

        if (!NtDllBase || !NtAlpcSendWaitReceivePortAddr) // we seem to need this last time i checked, return error.
            return false;


        bool Res = VirtualProtect(LPVOID(NtAlpcSendWaitReceivePortAddr), 8, NewProtection, OldProtectionOut); // yes i am lazy piece of shit.
        if (Res)
        {
            uint32_t OldSyscallIDX = *(uint32_t*)((NtAlpcSendWaitReceivePortAddr + 4)); // get old syscall

            *(uint32_t*)((NtAlpcSendWaitReceivePortAddr + 4)) = NewSyscallIDX; // swap the idx, 4 = sizeof mov r10 rcx, mov eax thesyscallidx

            *OriginalSyscallIDX = OldSyscallIDX; // copy the old syscall to the out, so we can restore if we need.
        }

        return Res;
    }

    namespace Syscaller
    {

        // IMPORTANT: THE SECOND ARG MUST BE 4 BYTES OR LESS. YOU CAN PROBABLY PASS 8 BYTES BUT EXPECT UNDEFINED BEHAVIOR IF YOU DO!!!!!!!!!!!!!!!!!
        template<typename ReturnType, typename... Args>
        __LIBPROT_FUNC ReturnType CallSyscallSafe(const char* TargetSyscallName, Args... args)
        {
            constexpr size_t arg_count = sizeof...(Args);
            static_assert(arg_count <= 8, "Too many arguments for NtAlpcSendWaitReceivePort syscall hijack");

            uintptr_t ntdllBase = LibProt::Internals::GetNTDllBaseAddress();
            if (!ntdllBase) return ReturnType();

#if !DO_NOT_INCLUDE_STR_CRYPTOR
            uintptr_t syscallStubAddr = LibProt::Internals::GetProcAddressByBase(ntdllBase, Encrypt("NtAlpcSendWaitReceivePort").decrypt()); // .decrypt() because im used to it ngl
#else
            uintptr_t syscallStubAddr = LibProt::Internals::GetProcAddressByBase(ntdllBase, "NtAlpcSendWaitReceivePort");
#endif
            if (!syscallStubAddr) return ReturnType();

            uint32_t targetSyscallIdx = LibProt::GetSyscallIDX(ntdllBase, TargetSyscallName);
            if (!targetSyscallIdx) return ReturnType(); // i do believe getting the target syscall is required and a slight issue if we can't, lets exit at ONCE.


            DWORD oldProtection = 0;
            uint32_t originalSyscallIdx = 0;

            // overwrite it
            if (!LibProt::OverwriteSyscall(targetSyscallIdx, &oldProtection, &originalSyscallIdx))
                return ReturnType(); // usually failing to overwrite causes an issue in my experience, lets kill ourselves at once!

            using FnCaller = ReturnType(__stdcall*)(Args...);
            auto syscallCaller = reinterpret_cast<FnCaller>(syscallStubAddr);

            // call hooked syscall, should point directly to our shit
            ReturnType result = syscallCaller(args...);

            // restore original syscall
            *(uint32_t*)((syscallStubAddr + 4)) = originalSyscallIdx;
            VirtualProtect(LPVOID(syscallStubAddr), 8, oldProtection, &oldProtection);

            return result;
        }
    }

    __LIBPROT_FUNC void CleanImportsAndExports(void* LocalModule, bool bCleanExports = true, bool bCleanTLSToo = true)
    {
        IMAGE_DOS_HEADER* DosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(LocalModule);
        IMAGE_NT_HEADERS* NtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>((PBYTE)DosHeader + DosHeader->e_lfanew);
        IMAGE_DATA_DIRECTORY* DataDirectory = NtHeader->OptionalHeader.DataDirectory;

        DWORD OriginalProtection = 0;
        if (!VirtualProtect(LocalModule, 0x1000, PAGE_EXECUTE_READWRITE, &OriginalProtection)) return; // we kinda have to be able to write yk?

        // destroy imports if it exists
        if (DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress || DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
        {

            DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = 0;
            DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = 0;
        }

        // destroy iat if it exists
        if (DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress || DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size)
        {
            DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = 0;
            DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size = 0;
        }

        // destroy tls if it exists and is requested.
        if (bCleanTLSToo && (DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress || DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size))
        {
            DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = 0;
            DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size = 0;
        }

        // destroy exports if it exists and is requested.
        if (bCleanExports && (DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress || DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size))
        {
            DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress = 0;
            DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size = 0;
        }

        VirtualProtect(LocalModule, 0x1000, OriginalProtection, &OriginalProtection); // restore
    }


    // cleans up our pe header, returns useless dumps for ida while passing nearly every intergrity check besides mem to disk and disk to mem.
    __LIBPROT_FUNC void CleanPE(void* LocalModule)
    {
        CopyKernel32Header(LocalModule);
    }

    // gets base addr of the main app, using PEB->ImageBaseAddress
    __LIBPROT_FUNC uintptr_t GetMainAppBase()
    {
        return reinterpret_cast<uintptr_t>(reinterpret_cast<LibProt::Definitions::PEB*>(__readgsqword(0x60))->ImageBaseAddress);
    }

    /*
    TODO: we want this 1 header, maybe we can find a way to inline asm or something ? maybe overwrite a legit syscall and call it? maybe allocate & overwrite this func ? idk
    do not set __LIBPROT_FUNC on it, this will make it useless.
    */
    int __placeholder_entry()
    {
        return 0; // mov rax, 0h, retn
    }


    // an effective detection for detecting packers & detecting anti debug, is that the entrypoint would be outside the module, this allows optionally 
    __LIBPROT_FUNC void DestroyEntryPoint(void* LocalBase, bool SetEntryPointInsideModule)
    {
        DWORD OriginalProtection = 0;
        if (!VirtualProtect(LocalBase, 0x1000, PAGE_EXECUTE_READWRITE, &OriginalProtection)) return; // we kinda have to be able to write yk?

        IMAGE_DOS_HEADER* DosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(LocalBase);
        IMAGE_NT_HEADERS* NtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>((PBYTE)DosHeader + DosHeader->e_lfanew);


        if (SetEntryPointInsideModule)
        {
            NtHeader->OptionalHeader.AddressOfEntryPoint = (DWORD)((uintptr_t)__placeholder_entry - uintptr_t(LocalBase)); // crazy method
        }
        else
        {
            // even crazier method ngl
            uintptr_t NTDllBase = LibProt::Internals::GetNTDllBaseAddress();
            if (!NTDllBase)
            {
                VirtualProtect(LocalBase, 0x1000, OriginalProtection, &OriginalProtection); // restore
                return;
            }

            IMAGE_DOS_HEADER* NtDllDosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(NTDllBase);
            IMAGE_NT_HEADERS* NtDllNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>((PBYTE)NtDllDosHeader + NtDllDosHeader->e_lfanew);

            // make it random-ish. TODO: you should probably change this.
            constexpr uintptr_t Factor = (__TIME__[4] * (__TIME__[1] * __LINE__) / 2);

            // insane casting purely because i don't want it to overflow.
            DWORD TargetAddressEntryFactor = static_cast<DWORD>(static_cast<unsigned long long>((uintptr_t)__placeholder_entry) - uintptr_t(LocalBase) + Factor); // would be target

            uintptr_t FinalTarget = static_cast<unsigned long long>((NtDllNtHeader->OptionalHeader.ImageBase + TargetAddressEntryFactor / 5)); // make sure its mostly small
            while (NtHeader->OptionalHeader.ImageBase >= (FinalTarget - 0x2000)) // check they aren't even close to our fake imagebase.
                FinalTarget += (Factor * 6); // random factor i guess.

            NtHeader->OptionalHeader.AddressOfEntryPoint = FinalTarget; // decent enoguh i suppose.
        }

        VirtualProtect(LocalBase, 0x1000, OriginalProtection, &OriginalProtection); // restore

        return;
    }

    __LIBPROT_FUNC void DestroyBaseAddressInMem(void* LocalBase)
    {
        LibProt::Definitions::PEB* peb = LibProt::Internals::GetPEB();

        
        // even crazier method ngl
        uintptr_t NTDllBase = LibProt::Internals::GetNTDllBaseAddress();
        if (!NTDllBase) return;
        
        IMAGE_DOS_HEADER* DllDosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(LocalBase);
        IMAGE_NT_HEADERS* DllNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>((PBYTE)DllDosHeader + DllDosHeader->e_lfanew);

        IMAGE_DOS_HEADER* NtDllDosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(NTDllBase);
        IMAGE_NT_HEADERS* NtDllNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>((PBYTE)NtDllDosHeader + NtDllDosHeader->e_lfanew);

        // make it random-ish. TODO: you should probably change this.
        constexpr uintptr_t Factor = (__TIME__[4] * (__TIME__[1] * __LINE__) / 2);

        // insane casting purely because i don't want it to overflow.
        DWORD TargetAddressEntryFactor = static_cast<DWORD>(static_cast<unsigned long long>((uintptr_t)__placeholder_entry) - uintptr_t(LocalBase) + Factor); // would be target

        uintptr_t FinalTarget = static_cast<unsigned long long>((NtDllNtHeader->OptionalHeader.ImageBase + TargetAddressEntryFactor / 5)); // make sure its mostly small
        while (DllNtHeader->OptionalHeader.ImageBase >= (FinalTarget - 0x2000)) // check they aren't even close to our fake imagebase.
            FinalTarget += (Factor * 6); // random factor i guess.


        uintptr_t Target = FinalTarget + 0x1800;

        LIST_ENTRY* current = peb->Ldr->InLoadOrderModuleList.Flink;

        while (current != &peb->Ldr->InLoadOrderModuleList)
        {
            auto entry = CONTAINING_RECORD(current, LibProt::Definitions::LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
            if (entry->DllBase == LocalBase)
            {
                entry->DllBase = reinterpret_cast<PVOID>(Target);
                break;
            }
            current = current->Flink;
        }

#if !_WINDLL // exe, im ngl i forgot the def.
        peb->ImageBaseAddress = reinterpret_cast<PVOID>(Target);
#endif

        return;
    }

    __LIBPROT_FUNC bool Initialize(void* LocalBase, bool SetEntryPointInsideModule, bool bCleanExportsToo = true, bool bCleanTLSToo = true)
    {
        if (!LocalBase) return false;

        // do it before, just incase, clear our own imports, optionally exports & tls too
        CleanImportsAndExports(LocalBase, bCleanExportsToo, bCleanTLSToo);

        CleanPE(LocalBase); // make the pe header as useless as battleye

        // clear our own imports, optionally exports & tls too
        CleanImportsAndExports(LocalBase, bCleanExportsToo, bCleanTLSToo);
        DestroyEntryPoint(LocalBase, SetEntryPointInsideModule);


        DestroyBaseAddressInMem(LocalBase);

        return true;
    }

    // nice lil 1 liner here, its cute.
    bool Initialize(uintptr_t LocalBase, bool SetEntryPointInsideModule, bool bCleanExportsToo = true, bool bCleanTLSToo = true) { return Initialize(reinterpret_cast<void*>(LocalBase), SetEntryPointInsideModule, bCleanExportsToo, bCleanTLSToo); };

    namespace PostInit
    {
        __LIBPROT_FUNC bool PostInitMakePEGuarded(void* LocalBase)
        {
            DWORD OriginalProtection = 0;
            return VirtualProtect(LocalBase, 0x1000, PAGE_GUARD, &OriginalProtection); // we kinda have to be able to write yk?

        }

        __LIBPROT_FUNC bool PostInitMakePENoAccess(void* LocalBase)
        {
            DWORD OriginalProtection = 0;
            return VirtualProtect(LocalBase, 0x1000, PAGE_NOACCESS, &OriginalProtection); // we kinda have to be able to write yk?
        }

        __LIBPROT_FUNC bool PostInitMakePEGuarded(uintptr_t LocalBase) { return LibProt::PostInit::PostInitMakePEGuarded(reinterpret_cast<void*>(LocalBase)); };
        __LIBPROT_FUNC bool PostInitMakePENoAccess(uintptr_t LocalBase) { return LibProt::PostInit::PostInitMakePENoAccess(reinterpret_cast<void*>(LocalBase)); };
    }
}