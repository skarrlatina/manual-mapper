#include "utils/Args.h"
#include "utils/logger/Logger.h"
#include "utils/Proc.h"
#include "loader/ImageLoader.h"
#include "mapper/ManualMap.h"

int wmain(int argc, wchar_t* argv[])
{
	auto argsOpt = ArgsData::Parse(argc, argv);

	if (!argsOpt)
		return 1;

	DWORD pid = GetProcessIdByName(argsOpt->target);
	HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

	std::vector<BYTE> dllBuffer;
	if (!ReadFileToMemory(argsOpt->path, dllBuffer))
	{
		logs::LogError(L"Failed to read file.");
		CloseHandle(processHandle);
		return 1;
	}


	ManualMapOptions options{};

	bool injected = ManualMapDll(
		processHandle,
		dllBuffer,
		options
	);

	if (injected)
		logs::LogSuccess(L"DLL injected successfully!");
	else
		logs::LogError(L"DLL injection failed.");

	return 0;
}