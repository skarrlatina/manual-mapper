#pragma once
#include "../common/Types.h"

void __stdcall Shellcode(ManualMapData* data);
void ShellcodeEnd();

bool ProcessRelocations(PBYTE imageBase, PIMAGE_OPTIONAL_HEADER optionalHeader, ManualMapData* mapData);
bool ProcessImports(PBYTE imageBase, PIMAGE_OPTIONAL_HEADER optionalHeader, ManualMapData* mapData, LoadLibraryAFunc loadLibrary, GetProcAddressFunc getProcAddress);
bool ProcessTlsCallbacks(PBYTE imageBase, PIMAGE_OPTIONAL_HEADER optionalHeader, ManualMapData* mapData);
#ifdef _WIN64
bool ProcessExceptions(PBYTE imageBase, PIMAGE_OPTIONAL_HEADER optionalHeader, ManualMapData* mapData, RtlAddFunctionTableFunc rtlAddFunctionTable);
#endif // _WIN64

void* InjectShellcode(HANDLE processHandle, const LPVOID shellcode, SIZE_T size);
HANDLE LaunchShellcodeThread(HANDLE processHandle, LPVOID shellcode, LPVOID mapData);
bool WaitForInjectionResult(HANDLE processHandle, HINSTANCE& outModule, LPVOID mapData, DWORD timeoutMs);