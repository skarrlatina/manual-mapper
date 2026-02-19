#pragma once
#include <Windows.h>
#include <vector>

#include "../common/Types.h"

bool ManualMapDll(HANDLE processHandle, const std::vector<BYTE>& dllBuffer, ManualMapOptions& options);
PBYTE WriteMapData(HANDLE processHandle, const ManualMapData& data);