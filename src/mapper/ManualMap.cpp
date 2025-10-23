#include "ManualMap.h"
#include "../utils/logs/Logger.h"
#include "../utils/ImageLoader.h"
#include "Shellcode.h"

bool ManualMapDll(HANDLE processHandle, const std::vector<BYTE>& dllBuffer, ManualMapOptions& options)
{
    auto localImage = (PBYTE)dllBuffer.data();
    PBYTE remoteImage = nullptr;
    PBYTE remoteMapData = nullptr;
    LPVOID remoteShellcode = nullptr;
    HANDLE shellThread = nullptr;
    bool success = false;

    logs::LogInfo("ManualMap: Starting DLL manual mapping process");

    if (!ValidatePEHeaders(localImage))
    {
        logs::LogError("ManualMap: PE headers validation failed.");
        return false;
    }
    logs::LogInfo("ManualMap: PE headers validated successfully");

    do
    {
        PIMAGE_NT_HEADERS ntHeaders = nullptr;
        remoteImage = AllocateAndWriteHeaders(processHandle, localImage, ntHeaders);
        if (!remoteImage)
        {
            logs::LogError("ManualMap: Failed to allocate memory or write PE headers. Code: %lu", GetLastError());
            break;
        }
        logs::LogInfo("ManualMap: PE headers allocated and written at 0x%p", remoteImage);

        if (!WriteSections(processHandle, localImage, remoteImage, ntHeaders))
        {
            logs::LogError("ManualMap: Failed to write PE sections to remote process. Error: %lu", GetLastError());
            break;
        }
        logs::LogSuccess("ManualMap: PE sections written successfully");

        // --- Shellcode data ---
        ManualMapData mapData{};
        mapData.loadLibrary = LoadLibraryA;
        mapData.getProcAddress = GetProcAddress;
#ifdef _WIN64
        mapData.rtlAddFunctionTable = (RtlAddFunctionTableFunc)RtlAddFunctionTable;
        logs::LogInfo("ManualMap: x64 mode - SEH support %s", options.enableSehSupport ? "enabled" : "disabled");
#else
        if (options.enableSehSupport)
        {
            logs::LogWarning("ManualMap: SEH support not available on x86 architecture");
        }
#endif
        mapData.baseImage = remoteImage;
        mapData.reason = options.reason;
        mapData.reserved = options.reserved;

        remoteMapData = WriteMapData(processHandle, mapData);
        if (!remoteMapData)
        {
            logs::LogError("ManualMap: Failed to write mapping data. Error: %lu", GetLastError());
            break;
        }
        logs::LogSuccess("ManualMap: Mapping data written at 0x%p", remoteMapData);

        SIZE_T shellcodeSize = (uintptr_t)&ShellcodeEnd - (uintptr_t)&Shellcode;
        logs::LogDebug("ManualMap: Shellcode size: %zu bytes", shellcodeSize);

        // --- Shellcode Injection ---
        remoteShellcode = InjectShellcode(processHandle, (LPVOID)&Shellcode, shellcodeSize);
        if (!remoteShellcode)
        {
            logs::LogError("ManualMap: Failed to inject shellcode. Error: %lu", GetLastError());
            break;
        }
        logs::LogSuccess("ManualMap: Shellcode injected at 0x%p", remoteShellcode);

        // --- Shellcode Thread ---
        shellThread = LaunchShellcodeThread(processHandle, remoteShellcode, remoteMapData);
        if (!shellThread)
        {
            logs::LogError("ManualMap: Failed to create remote thread. Error: %lu", GetLastError());
            break;
        }
        logs::LogSuccess("ManualMap: Remote thread created with ID: %lu", GetThreadId(shellThread));

        // --- Injection Result ---
        HINSTANCE checkHandle = nullptr;
        if (!WaitForInjectionResult(processHandle, checkHandle, remoteMapData, 10000))
        {
            logs::LogError("ManualMap: Injection failed or timed out");
            break;
        }
        logs::LogSuccess("ManualMap: DLL successfully loaded at 0x%p", checkHandle);

        if (options.clearHeader || options.clearUnusedSections)
        {
            ClearHeadersAndSections(processHandle, remoteImage, ntHeaders, 
                options.clearHeader, options.clearUnusedSections, options.enableSehSupport);

            logs::LogSuccess("ManualMap: Headers and sections cleared");
        }

        if (options.adjustProtections)
        {
            RestoreImageSectionProtections(processHandle, remoteImage, ntHeaders, options.enableSehSupport);
            logs::LogSuccess("ManualMap: Section protections restored");
        }

        success = true;
        logs::LogSuccess("ManualMap: Manual mapping completed successfully");

    } while (false);

    if (remoteImage)
    {
        VirtualFreeEx(processHandle, remoteMapData, 0, MEM_RELEASE);
        logs::LogDebug("ManualMap: Released mapping data memory");
    }

    if (remoteShellcode)
    {
        VirtualFreeEx(processHandle, remoteShellcode, 0, MEM_RELEASE);
        logs::LogDebug("ManualMap: Released shellcode memory");
    }

    if (shellThread)
    {
        CloseHandle(shellThread);
        logs::LogDebug("ManualMap: Closed thread handle");
    }

    if (!success)
    {
        logs::LogError("ManualMap: Manual mapping failed");
    }

    return success;
}

PBYTE WriteMapData(HANDLE processHandle, const ManualMapData& data)
{
    PBYTE remoteMemory = (PBYTE)VirtualAllocEx(processHandle, nullptr, sizeof(ManualMapData), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMemory)
        return nullptr;

    if (!WriteProcessMemory(processHandle, remoteMemory, &data, sizeof(ManualMapData), nullptr))
    {
        DWORD error = GetLastError();
        VirtualFreeEx(processHandle, remoteMemory, 0, MEM_RELEASE);
        return nullptr;
    }
    return remoteMemory;
}

void ClearHeadersAndSections(HANDLE processHandle, PBYTE remoteImage, PIMAGE_NT_HEADERS ntHeaders, bool clearHeaders, bool clearSections, bool SEHSupport)
{
    if (clearHeaders)
    {
        BYTE zeroHeader[0x1000] = { 0 }; // 4 KB
        WriteProcessMemory(processHandle, remoteImage, zeroHeader, 0x1000, nullptr);
    }

    if (clearSections)
    {
        auto sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
        for (UINT i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i)
        {
            SIZE_T sizeToClear = sectionHeader->Misc.VirtualSize;
            if (sectionHeader->Misc.VirtualSize)
            {
                if ((!SEHSupport && strcmp((char*)sectionHeader->Name, ".pdata") == 0) ||
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

void RestoreImageSectionProtections(HANDLE processHandle, PBYTE remoteImage, PIMAGE_NT_HEADERS ntHeaders, bool SEHSupport)
{
    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);

    for (UINT i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i)
    {
        if (sectionHeader->Misc.VirtualSize == 0)
            continue;

        DWORD oldProtect = 0;
        DWORD newProtect = PAGE_READONLY; // default

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
