#pragma once
#include "Colors.h"
#include <iostream>
#include <string>
#include <cstdarg>
#include <cstdio>

#define ENABLE_LOGS 1

namespace logs
{
#if ENABLE_LOGS
#define LOG_ERROR	    white << "[" << red << "ERROR" << white << "] "
#define LOG_INFO	    white << "[" << blue << "INFO" << white << "] "
#define LOG_SUCCESS		white << "[" << green << "SUCCESS" << white << "] "
#define LOG_WARNING		white << "[" << yellow << "WARN" << white << "] "
#define LOG_DEBUG		white << "[" << cyan << "DEBUG" << white << "] "

    inline void LogPrintf(const std::string& prefix, const char* fmt, ...)
    {
        constexpr size_t BUFFER_SIZE = 1024;
        char buffer[BUFFER_SIZE];

        va_list args;
        va_start(args, fmt);
        vsnprintf(buffer, BUFFER_SIZE, fmt, args);
        va_end(args);

        std::cout << prefix << buffer << std::endl;
    }
    template <typename... Args>
    inline void LogInfo(const char* fmt, Args... args)
    {
        constexpr size_t BUFFER_SIZE = 1024;
        char buffer[BUFFER_SIZE];

        std::snprintf(buffer, BUFFER_SIZE, fmt, args...);

        std::cout << LOG_INFO << buffer << std::endl;
    }

    template <typename... Args>
    inline void LogWarning(const char* fmt, ...)
    {
        constexpr size_t BUFFER_SIZE = 1024;
        char buffer[BUFFER_SIZE];

        va_list args;
        va_start(args, fmt);
        vsnprintf(buffer, BUFFER_SIZE, fmt, args);
        va_end(args);

        std::cout << LOG_WARNING << buffer << std::endl;
    }

    template <typename... Args>
    inline void LogError(const char* fmt, ...)
    {
        constexpr size_t BUFFER_SIZE = 1024;
        char buffer[BUFFER_SIZE];

        va_list args;
        va_start(args, fmt);
        vsnprintf(buffer, BUFFER_SIZE, fmt, args);
        va_end(args);

        std::cout << LOG_ERROR << buffer << std::endl;
    }

    template <typename... Args>
    inline void LogSuccess(const char* fmt, ...)
    {
        constexpr size_t BUFFER_SIZE = 1024;
        char buffer[BUFFER_SIZE];

        va_list args;
        va_start(args, fmt);
        vsnprintf(buffer, BUFFER_SIZE, fmt, args);
        va_end(args);

        std::cout << LOG_SUCCESS << buffer << std::endl;
    }

    template <typename... Args>
    inline void LogDebug(const char* fmt, ...)
    {
        constexpr size_t BUFFER_SIZE = 1024;
        char buffer[BUFFER_SIZE];

        va_list args;
        va_start(args, fmt);
        vsnprintf(buffer, BUFFER_SIZE, fmt, args);
        va_end(args);

        std::cout << LOG_DEBUG << buffer << std::endl;
    }

#else
    inline void LogInfo(const char*, ...) {}
    inline void LogWarning(const char*, ...) {}
    inline void LogError(const char*, ...) {}
    inline void LogSuccess(const char*, ...) {}
    inline void LogDebug(const char*, ...) {}
#endif
}
