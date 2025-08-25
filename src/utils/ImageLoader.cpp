#include "ImageLoader.h"
#include <fstream>

#ifdef _WIN64
#define CURRENT_ARCH IMAGE_FILE_MACHINE_AMD64
#else
#define CURRENT_ARCH IMAGE_FILE_MACHINE_I386
#endif

bool ReadFileToMemory(const std::wstring& filePath, std::vector<BYTE>& outBuffer)
{
	std::ifstream inputFile(filePath, std::ios::binary | std::ios::ate);
	if (!inputFile.is_open())
		return false;

	std::streamsize size = inputFile.tellg();
	inputFile.seekg(0, std::ios::beg);

	if (size <= 0)
		return false;

	outBuffer.resize(static_cast<size_t>(size));

	if (!inputFile.read(reinterpret_cast<CHAR*>(outBuffer.data()), size))
		return false;

	return true;
}

bool ValidatePEHeaders(PBYTE localImage)
{
	auto dosHeader = (PIMAGE_DOS_HEADER)localImage;

	if (dosHeader->e_magic != 0x5A4D) return false;
	auto ntHeaders = (PIMAGE_NT_HEADERS)(localImage + dosHeader->e_lfanew);
	if (ntHeaders->FileHeader.Machine != CURRENT_ARCH)
		return false;

	return true;
}

PBYTE AllocateAndWriteHeaders(HANDLE processHandle, PBYTE localImage, PIMAGE_NT_HEADERS& ntHeaders)
{
	auto dosHeader = (PIMAGE_DOS_HEADER)localImage;
	ntHeaders = (PIMAGE_NT_HEADERS)(localImage + dosHeader->e_lfanew);

	PBYTE remoteImage = (PBYTE)VirtualAllocEx(processHandle, nullptr, ntHeaders->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (remoteImage == nullptr)
		return nullptr;

	DWORD old = 0;
	VirtualProtectEx(processHandle, remoteImage, ntHeaders->OptionalHeader.SizeOfImage, PAGE_EXECUTE_READWRITE, &old);

	if (!WriteProcessMemory(processHandle, remoteImage, localImage, 0x1000, nullptr))
	{
		VirtualFreeEx(processHandle, remoteImage, 0, MEM_RELEASE);
		return nullptr;
	}
	return remoteImage;
}

bool WriteSections(HANDLE processHandle, PBYTE localImage, PBYTE remoteImage, PIMAGE_NT_HEADERS ntHeaders)
{
	auto sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
	for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i)
	{
		auto dst = remoteImage + sectionHeader[i].VirtualAddress;
		auto src = localImage + sectionHeader[i].PointerToRawData;
		SIZE_T size = sectionHeader[i].SizeOfRawData;
		if (!WriteProcessMemory(processHandle, (LPVOID)dst, (LPVOID)src, size, nullptr))
			return false;
	}
	return true;
}