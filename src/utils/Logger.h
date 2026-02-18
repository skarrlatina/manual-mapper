#pragma once
#include <iostream>
#include <format>
#include <string_view>

#define ENABLE_LOGGER 1

namespace logger
{
#if ENABLE_LOGGER
	
	template <typename... Args>
	void LogMessage(std::string_view prefix, std::string_view fmt, Args&&... args)
	{
		auto format_args = std::make_format_args(args...);
		std::string formatted = std::vformat(fmt, format_args);
		std::cout << prefix << formatted << std::endl;
	}
	
	// (ANSI escape codes)
	inline constexpr const char* r = "\033[31m"; // red
	inline constexpr const char* g = "\033[32m"; // green
	inline constexpr const char* y = "\033[33m"; // yellow
	inline constexpr const char* b = "\033[34m"; // blue
	inline constexpr const char* c = "\033[36m"; // cyan
	inline constexpr const char* w = "\033[37m"; // white

	template <typename... Args>
	inline void LogInfo(std::string_view fmt, Args&&... args) 
	{
		LogMessage(std::format("{}[{}INFO{}] ", w, b, w), fmt, std::forward<Args>(args)...);
	}

	template <typename... Args>
	inline void LogError(std::string_view fmt, Args&&... args) 
	{
		LogMessage(std::format("{}[{}ERROR{}] ", w, r, w), fmt, std::forward<Args>(args)...);
	}

	template <typename... Args>
	inline void LogSuccess(std::string_view fmt, Args&&... args) 
	{
		LogMessage(std::format("{}[{}SUCCESS{}] ", w, g, w), fmt, std::forward<Args>(args)...);
	}

	template <typename... Args>
	inline void LogWarning(std::string_view fmt, Args&&... args)
	{
		LogMessage(std::format("{}[{}WARN{}] ", w, y, w), fmt, std::forward<Args>(args)...);
	}

	template <typename... Args>
	inline void LogDebug(std::string_view fmt, Args&&... args)
	{
		LogMessage(std::format("{}[{}DEBUG{}] ", w, c, w), fmt, std::forward<Args>(args)...);
	}
#else
	template <typename... Args> inline void LogInfo(std::string_view, Args&&...) {}
	template <typename... Args> inline void LogError(std::string_view, Args&&...) {}
	template <typename... Args> inline void LogSuccess(std::string_view, Args&&...) {}
	template <typename... Args> inline void LogWarning(std::string_view, Args&&...) {}
	template <typename... Args> inline void LogDebug(std::string_view, Args&&...) {}
#endif
}
