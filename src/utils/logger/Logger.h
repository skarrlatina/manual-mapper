#pragma once
#include <iostream>
#include <format>
#include <string_view>

#define ENABLE_LOGS 1

namespace logs
{
#if ENABLE_LOGS
	
	template <typename... Args>
	void LogMessage(std::wstring_view prefix, std::wstring_view fmt, Args&&... args)
	{
		auto format_args = std::make_wformat_args(args...);
		std::wstring formatted = std::vformat(fmt, format_args);
		std::wcout << prefix << formatted << std::endl;
	}
	
	// (ANSI escape codes)
	inline constexpr const wchar_t* r = L"\033[31m";
	inline constexpr const wchar_t* g = L"\033[32m";
	inline constexpr const wchar_t* y = L"\033[33m";
	inline constexpr const wchar_t* b = L"\033[34m";
	inline constexpr const wchar_t* c = L"\033[36m";
	inline constexpr const wchar_t* w = L"\033[37m";

	template <typename... Args>
	inline void LogInfo(std::wstring_view fmt, Args&&... args) 
	{
		LogMessage(std::format(L"{}[{}INFO{}] ", w, b, w), fmt, std::forward<Args>(args)...);
	}

	template <typename... Args>
	inline void LogError(std::wstring_view fmt, Args&&... args) 
	{
		LogMessage(std::format(L"{}[{}ERROR{}] ", w, r, w), fmt, std::forward<Args>(args)...);
	}

	template <typename... Args>
	inline void LogSuccess(std::wstring_view fmt, Args&&... args) 
	{
		LogMessage(std::format(L"{}[{}SUCCESS{}] ", w, g, w), fmt, std::forward<Args>(args)...);
	}

	template <typename... Args>
	inline void LogWarning(std::wstring_view fmt, Args&&... args)
	{
		LogMessage(std::format(L"{}[{}WARN{}] ", w, y, w), fmt, std::forward<Args>(args)...);
	}

	template <typename... Args>
	inline void LogDebug(std::wstring_view fmt, Args&&... args)
	{
		LogMessage(std::format(L"{}[{}DEBUG{}] ", w, c, w), fmt, std::forward<Args>(args)...);
	}
#else
	template <typename... Args> inline void LogInfo(std::wstring_view, Args&&...) {}
	template <typename... Args> inline void LogError(std::wstring_view, Args&&...) {}
	template <typename... Args> inline void LogSuccess(std::wstring_view, Args&&...) {}
	template <typename... Args> inline void LogWarning(std::wstring_view, Args&&...) {}
	template <typename... Args> inline void LogDebug(std::wstring_view, Args&&...) {}
#endif
}
