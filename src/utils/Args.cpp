#include "Args.h"
#include "logger/Logger.h"

std::optional<ArgsData> ArgsData::Parse(int argc, wchar_t* argv[])
{
	ArgsData data;
	
	for (int i = 1; i < argc; ++i)
	{
		std::wstring arg = argv[i];

		//logs::LogDebug(L"Agrument Nums: {}", argc);
		//logs::LogInfo(L"Parsing argument: {}", arg);
		if (arg == L"--path" && i + 1 < argc)
			data.path = argv[++i];

		else if (arg == L"--target" && i + 1 < argc)
			data.target = argv[++i];

		else
		{
			logs::LogError(L"[-] Unknown argument: {}", arg);
			return std::nullopt;
		}
	}

	if (data.path.empty() || data.target.empty())
	{
		logs::LogError(L"[-] Missing required arguments: --path and --target");
		return std::nullopt;
	}

	return data;
}
