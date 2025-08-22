#include "ProcessUtils.h"
#include <TlHelp32.h>

DWORD GetProcessIdByName(const std::wstring& processName)
{
	DWORD pid = 0;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot != INVALID_HANDLE_VALUE)
	{
		PROCESSENTRY32W entry;
		entry.dwSize = sizeof(entry);
		if (Process32FirstW(hSnapshot, &entry))
		{
			do
			{
				if (!processName.compare(entry.szExeFile))
				{
					pid = entry.th32ProcessID;
					break;
				}
			} while (Process32NextW(hSnapshot, &entry));
		}
	}
	CloseHandle(hSnapshot);
	return pid;
}
