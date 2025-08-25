#pragma once
#include <Windows.h>

constexpr uintptr_t EXCEPTION_SETUP_FAILED_VALUE = 0x505050;

using LoadLibraryAFunc = HINSTANCE(WINAPI*)(const char* libraryName);
using GetProcAddressFunc = FARPROC(WINAPI*)(HMODULE module, LPCSTR procName);
using DllEntryPointFunc = BOOL(WINAPI*)(LPVOID dllHandle, DWORD reason, LPVOID reserved);

#ifdef _WIN64
using RtlAddFunctionTableFunc = BOOL(WINAPI*)(PRUNTIME_FUNCTION functionTable, DWORD entryCount, DWORD64 baseAddress);
using RtlDeleteFunctionTableFunc = BOOL(WINAPI*)(PRUNTIME_FUNCTION functionTable);
#endif

enum class ManualMapError
{
    SUCCESS = 0,
    INVALID_PARAMETER,
    INVALID_PE_HEADERS,
    RELOCATION_FAILED,
    IMPORT_RESOLUTION_FAILED,
    TLS_INIT_FAILED,
    EXCEPTION_SUPPORT_FAILED,
    DLL_MAIN_FAILED,
    UNKNOWN_ERROR
};

struct ManualMapOptions
{
    bool clearHeader = true;
    bool clearUnusedSections = true;
    bool adjustProtections = true;
    bool enableSehSupport = true;
    bool enableTlsCallbacks = true;

    DWORD reason = DLL_PROCESS_ATTACH;
    LPVOID reserved = nullptr;
};

struct ManualMapData
{
    LoadLibraryAFunc loadLibrary;
    GetProcAddressFunc getProcAddress;

#ifdef _WIN64
    RtlAddFunctionTableFunc rtlAddFunctionTable;
    RtlDeleteFunctionTableFunc rtlDeleteFunctionTable;
#endif

    PBYTE baseImage;
    PBYTE entryPoint;
    HINSTANCE moduleHandle;

    DWORD reason;
    LPVOID reserved;

    BOOL enableSehSupport;
    BOOL enableTlsCallbacks;

    ManualMapError errorCode;
    DWORD lastWin32Error;
};