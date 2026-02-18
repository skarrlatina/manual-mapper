#include "utils/Args.h"
#include "utils/Logger.h"

int main(int argc, char* argv[])
{
	//auto argsOpt = ArgsData::Parse(argc, argv);

	//if (!argsOpt)
	//	return 1;

	ArgsData args = { .path = "test.dll", .target = "proc.exe"};
	logger::LogInfo("[*] ", "Path: {}, Target: {}", args.path, args.target);

	return 0;
}