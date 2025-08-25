#include "Shellcode.h"
#include "../utils/logs/Logger.h"

// --- RELOCATIONS ---
bool ProcessRelocations(PBYTE imageBase, PIMAGE_OPTIONAL_HEADER optionalHeader, ManualMapData* mapData)
{
    if (!imageBase || !optionalHeader || !mapData)
    {
        return false;
    }

    auto relocDir = optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (relocDir.VirtualAddress == 0 || relocDir.Size == 0)
    {
        return true;
    }

    auto relocBlock = (PIMAGE_BASE_RELOCATION)(imageBase + relocDir.VirtualAddress);
    SIZE_T relocBytesLeft = relocDir.Size;

    while (relocBytesLeft > 0 && relocBlock && relocBlock->SizeOfBlock > 0)
    {
        if (relocBlock->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION))
        {
            return false;
        }

        DWORD count = (relocBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        WORD* entries = (WORD*)(relocBlock + 1);

        for (UINT i = 0; i < count; ++i)
        {
            WORD entry = entries[i];
            DWORD type = entry >> 12;
            DWORD offset = entry & 0xFFF;

            if (type == IMAGE_REL_BASED_DIR64)
            {
                ULONGLONG* patchAddr = (ULONGLONG*)(imageBase + relocBlock->VirtualAddress + offset);
                *patchAddr += (ULONGLONG)(imageBase - optionalHeader->ImageBase);
            }
        }
        relocBytesLeft -= relocBlock->SizeOfBlock;
        relocBlock = (PIMAGE_BASE_RELOCATION)((PBYTE)relocBlock + relocBlock->SizeOfBlock);
    }
    return true;
}

// --- IMPORTS ---
bool ProcessImports(PBYTE imageBase, PIMAGE_OPTIONAL_HEADER optionalHeader,
    ManualMapData* mapData, LoadLibraryAFunc loadLibrary, GetProcAddressFunc getProcAddress)
{
    if (!imageBase || !optionalHeader || !mapData || !loadLibrary || !getProcAddress)
    {
        return false;
    }

    auto importDir = optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir.Size == 0)
    {
        return true;
    }

    auto importDesc = (PIMAGE_IMPORT_DESCRIPTOR)(imageBase + importDir.VirtualAddress);

    while (importDesc->Name)
    {
        LPCSTR moduleName = (LPCSTR)(imageBase + importDesc->Name);
        HMODULE mod = loadLibrary(moduleName);

        if (!mod)
        {
            return false;
        }

        auto thunkRef = (PIMAGE_THUNK_DATA)(imageBase + importDesc->OriginalFirstThunk);
        auto funcRef = (PIMAGE_THUNK_DATA)(imageBase + importDesc->FirstThunk);

        if (!thunkRef)
            thunkRef = funcRef;

        while (thunkRef->u1.AddressOfData)
        {
            FARPROC funcAddr = nullptr;

            if (thunkRef->u1.Ordinal & IMAGE_ORDINAL_FLAG)
            {
                WORD ordinal = IMAGE_ORDINAL(thunkRef->u1.Ordinal);
                funcAddr = getProcAddress(mod, (LPCSTR)ordinal);
            }
            else
            {
                auto importByName = (PIMAGE_IMPORT_BY_NAME)(imageBase + thunkRef->u1.AddressOfData);
                funcAddr = getProcAddress(mod, importByName->Name);
            }

            if (!funcAddr)
            {
                return false;
            }

#ifdef _WIN64
            funcRef->u1.Function = (ULONGLONG)funcAddr;
#else
            funcRef->u1.Function = (DWORD)funcAddr;
#endif
            ++thunkRef;
            ++funcRef;
        }
        ++importDesc;
    }
    return true;
}

// --- CALLBACKS ---
bool ProcessTlsCallbacks(PBYTE imageBase, PIMAGE_OPTIONAL_HEADER optionalHeader, ManualMapData* mapData)
{
    if (!imageBase || !optionalHeader || !mapData)
    {
        return false;
    }

    auto tlsDir = optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (tlsDir.Size == 0)
    {
        return true;
    }

    auto tlsDirectory = reinterpret_cast<PIMAGE_TLS_DIRECTORY>(imageBase + tlsDir.VirtualAddress);
    auto callbacks = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(tlsDirectory->AddressOfCallBacks);

    if (callbacks)
    {
        for (; *callbacks; ++callbacks)
            (*callbacks)(imageBase, DLL_PROCESS_ATTACH, nullptr);
    }
    return true;
}

// --- SEH ---
#ifdef _WIN64
bool ProcessExceptions(PBYTE imageBase, PIMAGE_OPTIONAL_HEADER optionalHeader,
    ManualMapData* mapData, RtlAddFunctionTableFunc rtlAddFunctionTable)
{
    if (!imageBase || !optionalHeader || !mapData || !rtlAddFunctionTable)
    {
        return false;
    }

    if (!mapData->enableSehSupport)
    {
        return true;
    }

    auto exceptionDir = optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (exceptionDir.Size == 0)
    {
        return true;
    }

    bool exceptionFailed = false;
    if (!rtlAddFunctionTable(
        (PIMAGE_RUNTIME_FUNCTION_ENTRY)(imageBase + exceptionDir.VirtualAddress),
        exceptionDir.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY),
        (DWORD64)(imageBase)))
    {
        exceptionFailed = true;
    }
 
#ifdef _WIN64
    mapData->moduleHandle = exceptionFailed ? reinterpret_cast<HINSTANCE>(0x505050) : reinterpret_cast<HINSTANCE>(imageBase);
#else
    mapData->moduleHandle = reinterpret_cast<HINSTANCE>(pBase);
#endif

    return !exceptionFailed ? true : false;
}
#endif

void __stdcall Shellcode(ManualMapData* mapData)
{
    if (!mapData)
        return;

    mapData->errorCode = ManualMapError::UNKNOWN_ERROR;
    mapData->lastWin32Error = ERROR_SUCCESS;

    PBYTE imageBase = mapData->baseImage;
    if (!imageBase)
    {
        return;
    }

    auto dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(imageBase);
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        return;
    }

    auto ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(imageBase + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        return;
    }

    auto optionalHeader = &ntHeaders->OptionalHeader;

    if (!ProcessRelocations(imageBase, optionalHeader, mapData))
        return;

    if (!ProcessImports(imageBase, optionalHeader, mapData, mapData->loadLibrary, mapData->getProcAddress))
        return;

    if (mapData->enableTlsCallbacks)
    {
        if (!ProcessTlsCallbacks(imageBase, optionalHeader, mapData))
            return;
    }

#ifdef _WIN64
    ProcessExceptions(imageBase, optionalHeader, mapData, mapData->rtlAddFunctionTable);
#endif

    auto dllMain = (DllEntryPointFunc)(imageBase + optionalHeader->AddressOfEntryPoint);
    BOOL dllMainResult = dllMain(imageBase, mapData->reason, mapData->reserved);

    if (!dllMainResult)
    {
        return;
    }
}

void ShellcodeEnd()
{
}

void* InjectShellcode(HANDLE processHandle, const LPVOID shellcode, SIZE_T size)
{
	void* remote = VirtualAllocEx(processHandle, nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!remote) return nullptr;
	if (!WriteProcessMemory(processHandle, remote, shellcode, size, nullptr))
	{
		VirtualFreeEx(processHandle, remote, 0, MEM_RELEASE);
		return nullptr;
	}
	return remote;
}

HANDLE LaunchShellcodeThread(HANDLE processHandle, LPVOID shellcode, LPVOID mapData)
{
	return CreateRemoteThread(processHandle, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(shellcode), mapData, 0, nullptr);
}

bool WaitForInjectionResult(HANDLE processHandle, HINSTANCE& outModule, LPVOID mapData, DWORD timeoutMs)
{
	ManualMapData dataChecked;
	DWORD startTime = GetTickCount();

	while (true)
	{
		DWORD exitCode = 0;
		if (!GetExitCodeProcess(processHandle, &exitCode) || exitCode != STILL_ACTIVE) 
            return false;

		if (!ReadProcessMemory(processHandle, mapData, &dataChecked, sizeof(dataChecked), nullptr)) 
            return false;

		if (dataChecked.moduleHandle == reinterpret_cast<HINSTANCE>(0x505050)) 
        {
            logs::LogError("ManualMap: Module loaded, but exception handling setup failed.");
			outModule = nullptr;
			return true;
		}

		if (dataChecked.moduleHandle != nullptr) 
        {
			outModule = dataChecked.moduleHandle;
            logs::LogError("ManualMap: Module handle = %p", outModule);
			return true;
		}

		if (GetTickCount() - startTime > timeoutMs) 
        {
			logs::LogError("ManualMap: Injection timeout");
			return false;
		}

		WaitForSingleObject(processHandle, 100);
	}
}