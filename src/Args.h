#pragma once
#include <iostream>
#include <optional>
#include <string>

struct ArgsData
{
	std::string path;
	std::string target;

	static std::optional<ArgsData> Parse(int argc, char* argv[]);
};