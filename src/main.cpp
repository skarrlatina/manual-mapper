#include "mapper/ManualMap.h"
#include "utils/ProcessUtils.h"
#include "utils/ImageLoader.h"
#include "utils/logs/Logger.h"
#include <iostream>

int main(int argc, char* argv[])
{
	DWORD pid = GetProcessIdByName(L"mspaint.exe");
	if (!pid)
	{
		logs::LogError("Process not found.");
		return 1;
	}

	HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (processHandle == NULL)
	{
		logs::LogError("Failed to open process.");
		return 1;
	}

	std::vector<BYTE> dllBuffer;
	if (!ReadFileToMemory(L"C:\\testDll.dll", dllBuffer))
	{
		logs::LogError("Failed to read file.");
		CloseHandle(processHandle);
		return 1;
	}

	ManualMapOptions options{};
	bool injected = ManualMapDll(
		processHandle,
		dllBuffer,
		options
	);

	if (processHandle)
		CloseHandle(processHandle);
}
