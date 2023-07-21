#pragma once

#include "argparse.h"
#include "EncodingUtils.h"
#include <string>
#include <vector>
#include <windows.h>

#pragma pack(push, 1)
struct IchigoArguments
{
    wchar_t WorkDirectory[MAX_PATH];
    BOOL Quiet;
    BOOL OnlyPE;
    DWORD PID;
    struct
    {
        BOOL StopAtWrite;
    } Unhollow;
};
#pragma pack(pop)

class ShinigamiArguments {
public:
    ShinigamiArguments();
    const std::wstring& GetTarget() const;
    const std::wstring& GetWorkDirectory() const { return WorkDirectory; }
    const std::vector<std::wstring>& GetTargetArgs() const { return TargetArguments; }
    const IchigoArguments& GetIchigoArguments() const { return IchiArguments; }


    void ParseArguments(int argc, char* argv[], const char* ProgramName);

public:
    // Shinigami specific arguments for process creation and so on
    std::wstring TargetExecutableName;
    std::wstring WorkDirectory;
    std::wstring OutputDirectory;
    std::wstring ExportedFunction;
    std::vector<std::wstring> TargetArguments;

    // Ichigo arguments that will be sent to the injected code
private:
    IchigoArguments IchiArguments;

};

