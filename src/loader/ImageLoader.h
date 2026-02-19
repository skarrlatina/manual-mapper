#pragma once
#include <Windows.h>
#include <string>
#include <vector>

bool ReadFileToMemory(const std::wstring& filePath, std::vector<BYTE>& outBuffer);
bool ValidatePEHeaders(PBYTE localImage);
PBYTE AllocateAndWriteHeaders(HANDLE process, PBYTE localImage, PIMAGE_NT_HEADERS& ntHeaders);
bool WriteSections(HANDLE process, PBYTE localImage, PBYTE remoteImage, PIMAGE_NT_HEADERS ntHeaders);