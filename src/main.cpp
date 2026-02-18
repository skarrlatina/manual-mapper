#include <iostream>
#include <optional>

#include "Args.h"

int main(int argc, char* argv[])
{
	auto argsOpt = ArgsData::Parse(argc, argv);

	if (!argsOpt)
		return 1;

	ArgsData args = *argsOpt;
	std::cout << "[+] Path: " << args.path << std::endl;
	std::cout << "[+] Target: " << args.target << std::endl;

	return 0;
}