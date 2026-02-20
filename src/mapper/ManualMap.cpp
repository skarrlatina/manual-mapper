#include "ManualMap.h"
#include "../loader/ImageLoader.h"
#include "../utils/logger/Logger.h"
#include "Shellcode.h"

bool ManualMapDll(HANDLE processHandle, const std::vector<BYTE>& dllBuffer, ManualMapOptions& options)
{
    auto localImage = (PBYTE)dllBuffer.data();
    PBYTE remoteImage = nullptr;
    PBYTE remoteMapData = nullptr;
    LPVOID remoteShellcode = nullptr;
    HANDLE shellThread = nullptr;
    bool success = false;

	logs::LogInfo(L"[*] Starting manual mapping of the DLL...");

    if (!ValidatePEHeaders(localImage))
    {
		logs::LogError(L"[!] Invalid PE headers. Aborting manual mapping.");
        return success;
    }

	logs::LogInfo(L"[*] PE headers validated successfully.");

    do
    {
        PIMAGE_NT_HEADERS ntHeaders = nullptr;
        remoteImage = AllocateAndWriteHeaders(processHandle, localImage, ntHeaders);

        if (!remoteImage)
        {
			logs::LogError(L"[!] Failed to allocate and write headers. Code: {}", GetLastError());
            break;
        }

		logs::LogDebug(L"[*] Headers allocated and written at remote address: {:p}", (void*)remoteImage);

        if (!WriteSections(processHandle, localImage, remoteImage, ntHeaders))
        {
			logs::LogError(L"[!] Failed to write sections. Code: {}", GetLastError());
            break;
        }

		logs::LogDebug(L"[*] Sections written successfully.");

        // --- Shellcode data ---
        ManualMapData mapData{};
        mapData.loadLibrary = LoadLibraryA;
        mapData.getProcAddress = GetProcAddress;
#ifdef _WIN64
        mapData.rtlAddFunctionTable = (RtlAddFunctionTableFunc)RtlAddFunctionTable;
		logs::LogDebug(L"[*] RtlAddFunctionTable address: {:p}", (void*)mapData.rtlAddFunctionTable);
		logs::LogDebug(L"[*] SEH support enabled: {}", options.enableSehSupport);
#else
        if (options.enableSehSupport)
        {
			logs::LogWarning(L"[!] SEH support is not available on 32-bit architecture. Ignoring this option.");
        }
#endif
		mapData.baseImage = remoteImage;
        mapData.reason = options.reason;
        mapData.reserved = options.reserved;

        remoteMapData = WriteMapData(processHandle, mapData);
        if (!remoteMapData)
        {
			logs::LogDebug(L"[!] Failed to write map data. Code: {}", GetLastError());
			break;
        }
        logs::LogDebug(L"[*] Map data written at remote address: {:p}", (void*)remoteMapData);

        // --- Shellcode ---
        SIZE_T shellcodeSize = (uintptr_t)&ShellcodeEnd - (uintptr_t)&Shellcode;
		logs::LogDebug(L"[*] Shellcode size: {} bytes", shellcodeSize);

        remoteShellcode = InjectShellcode(processHandle, (LPVOID)&Shellcode, shellcodeSize);
        if (!remoteShellcode)
        {
			logs::LogError(L"[!] Failed to inject shellcode. Code: {}", GetLastError());
            break;
        }
        logs::LogDebug(L"[*] Shellcode injected at remote address: {:p}", (void*)remoteShellcode);

        shellThread = LaunchShellcodeThread(processHandle, remoteShellcode, remoteMapData);
        if (!shellThread)
        {
            logs::LogError(L"[!] Failed to launch shellcode thread. Code: {}", GetLastError());
            break;
        }
        logs::LogInfo(L"[*] Shellcode thread launched successfully. Waiting for initialization...");

        HINSTANCE remoteModule = nullptr;
        if (!WaitForInjectionResult(processHandle, shellThread, remoteModule, remoteMapData, 15000))
        {
            logs::LogError(L"[!] Shellcode execution failed or timed out.");
            success = false;
			break;
        }
        logs::LogSuccess(L"[+] DLL injected successfully at remote address: {:p}", (void*)remoteModule);
        success = true;

    } while (false);

    return success;
}

PBYTE WriteMapData(HANDLE processHandle, const ManualMapData& data)
{
    PBYTE remoteMemory = (PBYTE)VirtualAllocEx(processHandle, nullptr, sizeof(ManualMapData), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMemory) return nullptr;

    if (!WriteProcessMemory(processHandle, remoteMemory, &data, sizeof(ManualMapData), nullptr))
    {
        VirtualFreeEx(processHandle, remoteMemory, 0, MEM_RELEASE);
        return nullptr;
    }
	return remoteMemory;
}

void ClearHeadersAndSections(HANDLE processHandle, PBYTE remoteImage, PIMAGE_NT_HEADERS ntHeaders, bool clearHeaders, bool clearSections, bool clearSeh)
{
    if (clearHeaders)
    {
        DWORD sizeOfHeaders = ntHeaders->OptionalHeader.SizeOfHeaders;
        std::vector<BYTE> zeroBuffer(sizeOfHeaders, 0);

        if (!WriteProcessMemory(processHandle, remoteImage, zeroBuffer.data(), sizeOfHeaders, nullptr))
        {
            logs::LogError(L"Failed to clear headers. Error: {}", GetLastError());
        }
    }

    if (clearSections)
    {
        auto sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
        for (UINT i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i)
        {
            SIZE_T sizeToClear = sectionHeader->Misc.VirtualSize;
            if (sectionHeader->Misc.VirtualSize)
            {
                if ((!clearSeh && strcmp((char*)sectionHeader->Name, ".pdata") == 0) ||
                    strcmp((char*)sectionHeader->Name, ".rsrc") == 0 ||
                    strcmp((char*)sectionHeader->Name, ".reloc") == 0)
                {
                    BYTE* emptyBuffer = (BYTE*)malloc(sizeToClear);
                    if (emptyBuffer)
                    {
                        memset(emptyBuffer, 0, sizeToClear);
                        WriteProcessMemory(processHandle, remoteImage + sectionHeader->VirtualAddress, emptyBuffer, sizeToClear, nullptr);
                        free(emptyBuffer);
                    }
                }
            }
            ++sectionHeader;
        }
    }
}

void RestoreImageSectionProtections(HANDLE processHandle, PBYTE remoteImage, PIMAGE_NT_HEADERS ntHeaders, bool sehSupport)
{
    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);

    for (UINT i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i)
    {
        if (sectionHeader->Misc.VirtualSize == 0)
            continue;

        DWORD oldProtect = 0;
        DWORD newProtect = PAGE_READONLY;

        if (sectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE)
            newProtect = PAGE_READWRITE;
        else if (sectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE)
            newProtect = PAGE_EXECUTE_READ;

        VirtualProtectEx(processHandle, remoteImage + sectionHeader->VirtualAddress, sectionHeader->Misc.VirtualSize, newProtect, &oldProtect);
    }

    DWORD oldProtect = 0;
    SIZE_T headerSize = IMAGE_FIRST_SECTION(ntHeaders)->VirtualAddress;
    VirtualProtectEx(processHandle, remoteImage, headerSize, PAGE_READONLY, &oldProtect);
}
