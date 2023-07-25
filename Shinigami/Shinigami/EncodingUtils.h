#pragma once
#include <string>
#include <vector>
#include <Windows.h>

namespace EncodingUtils {

    // Convert std::string to std::wstring
    std::wstring StringToWstring(const std::string& str);

    // Convert std::wstring to std::string
    std::string WstringToString(const std::wstring& wstr);

    // Convert char* to wchar_t*
    wchar_t* CharToWchar(const char* str);

    // Convert wchar_t* to char*
    char* WcharToChar(const wchar_t* wstr);

    // Split string
    std::vector<std::wstring> SplitWide(std::wstring String, const std::wstring& delimiter);
}
