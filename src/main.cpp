#include "utils/Args.h"
#include "utils/logger/Logger.h"
#include "utils/Proc.h"
#include "loader/ImageLoader.h"
#include "mapper/ManualMap.h"

bool ExecuteInjection(const ArgsData& args)
{
	DWORD pid = GetProcessIdByName(args.target);
	if (pid == 0) 
	{
		logs::LogError(L"Process '{}' not found.", args.target);
		return false;
	}

	HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (!processHandle) 
	{
		logs::LogError(L"Failed to open process. Error: {}", GetLastError());
		return false;
	}

	std::vector<BYTE> dllBuffer;
	if (!ReadFileToMemory(args.path, dllBuffer)) 
	{
		logs::LogError(L"Failed to read DLL file.");
		CloseHandle(processHandle);
		return false;
	}

	ManualMapOptions options{};
	bool result = ManualMapDll(processHandle, dllBuffer, options);

	CloseHandle(processHandle);
	return result;
}

int wmain(int argc, wchar_t* argv[])
{
	auto argsOpt = ArgsData::Parse(argc, argv);

	if (!argsOpt)
		return 1;

	logs::LogInfo(L"Starting injection process...");

	if (ExecuteInjection(*argsOpt)) 
		logs::LogSuccess(L"Injection completed successfully.");
	else return 1;

	return 0;
}