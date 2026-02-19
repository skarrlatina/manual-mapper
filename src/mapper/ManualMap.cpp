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
        return false;
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
			break;
        }
        logs::LogSuccess(L"[+] DLL injected successfully at remote address: {:p}", (void*)remoteModule);

    } while (false);
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
