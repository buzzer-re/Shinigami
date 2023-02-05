#pragma once

#include <Windows.h>
#include <string>

class Injector
{
	Injector(const std::wstring& procName);
	bool InjectSuspended(const std::wstring& dllPath);

};

