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
	PIMAGE_DOS_HEADER DosHdr;
	BYTE* Buff;
	BOOL Valid;
	std::wstring Path;
};
