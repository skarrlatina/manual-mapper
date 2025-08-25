#pragma once
#include "../common/Types.h"
#include <vector>

bool ManualMapDll(HANDLE processHandle, const std::vector<BYTE>& dllBuffer, ManualMapOptions& options);
PBYTE WriteMapData(HANDLE processHandle, const ManualMapData& data);

void ClearHeadersAndSections(HANDLE processHandle, PBYTE remoteImage, PIMAGE_NT_HEADERS ntHeaders, bool clearHeaders, bool clearSections, bool clearSeh);
void RestoreImageSectionProtections(HANDLE processHandle, PBYTE remoteImage, PIMAGE_NT_HEADERS ntHeaders, bool sehSupport);