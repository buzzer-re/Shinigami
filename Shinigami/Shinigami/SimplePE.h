#pragma once
#include <windows.h>
#include <string>

class SimplePE
{
public:
	SimplePE(const std::wstring& Path);
	BOOL IsValid() const { return Valid;  }
	BOOL IsDLL() const;
private:
	BOOL Load();
private:
	IMAGE_DOS_HEADER DosHdr;
	IMAGE_NT_HEADERS NtHeader;
	BYTE* Buff;
	BOOL Valid;
	BOOL DLL;
	std::wstring Path;
};
