#include "Args.h"

std::optional<ArgsData> ArgsData::Parse(int argc, char* argv[])
{
	ArgsData data;

	if(argc <= 0)

	for (int i = 1; i < argc; ++i)
	{
		std::string arg = argv[i];

		if (arg == "--path" && i + 1 < argc)
			data.path = argv[++i];

		else if (arg == "--target" && i + 1 < argc)
			data.target = argv[++i];

		else
		{
			std::cerr << "[-] Unknown argument: " << arg << std::endl;
			return std::nullopt;
		}
	}

	if (data.path.empty() || data.target.empty())
	{
		std::cerr << "[-] Missing required arguments: --path and --target" << std::endl;
		return std::nullopt;
	}

	return data;
}
