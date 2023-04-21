#include "EncodingUtils.h"

namespace EncodingUtils {

    std::wstring StringToWstring(const std::string& str) {
        int wstrSize = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, nullptr, 0);
        std::wstring wstr(wstrSize, 0);
        MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &wstr[0], wstrSize);
        return wstr;
    }

    std::string WstringToString(const std::wstring& wstr) {
        int strSize = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, nullptr, 0, nullptr, nullptr);
        std::string str(strSize, 0);
        WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &str[0], strSize, nullptr, nullptr);
        return str;
    }

    wchar_t* CharToWchar(const char* str) {
        int wstrSize = MultiByteToWideChar(CP_UTF8, 0, str, -1, nullptr, 0);
        wchar_t* wstr = new wchar_t[wstrSize];
        MultiByteToWideChar(CP_UTF8, 0, str, -1, wstr, wstrSize);
        return wstr;
    }

    char* WcharToChar(const wchar_t* wstr) {
        int strSize = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, nullptr, 0, nullptr, nullptr);
        char* str = new char[strSize];
        WideCharToMultiByte(CP_UTF8, 0, wstr, -1, str, strSize, nullptr, nullptr);
        return str;
    }

}
