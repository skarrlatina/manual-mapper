#pragma once
#include <iostream>
#include <optional>
#include <string>

struct ArgsData
{
	std::wstring path;
	std::wstring target;

	static std::optional<ArgsData> Parse(int argc, wchar_t* argv[]);
} inline g_Args;