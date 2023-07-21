#include "ShinigamiArguments.h"


ShinigamiArguments::ShinigamiArguments()
{
    wchar_t cwd[MAX_PATH];
    GetCurrentDirectoryW(MAX_PATH, cwd);
    WorkDirectory = cwd;
}

const std::wstring& ShinigamiArguments::GetTarget() const
{
    // First verify if there is arguments here

    return TargetArguments[0];
}

void ShinigamiArguments::ParseArguments(int argc, char* argv[], const char* ProgamName) 
{
    argparse::ArgumentParser parser(ProgamName);
    parser.add_argument("program_name")
        .help("Name of the program to execute");
    parser.add_argument("--output", "-o")
        .help("Directory to dump artefacts");
    parser.add_argument("--stop-at-write")
        .implicit_value(true)
        .default_value(false)
        .help("Unhollow: Stop the execution when the PE file is being to be written");
    parser.add_argument("--verbose")
        .implicit_value(true)
        .default_value(false)
        .help("Display a verbose output");
    parser.add_argument("--only-executables", "-p")
        .implicit_value(true)
        .default_value(false)
        .help("Only extract PE artefacts");
    parser.add_argument("--exported", "-e")
        .help("Exported Function: Choose a exported function to execute if the target is a DLL (rundll will be used)");

    try {
        parser.parse_args(argc, argv);
    }
    catch (const std::runtime_error& e) {
        throw std::runtime_error(std::string("Error parsing arguments: ") + e.what());
    }

    TargetExecutableName = EncodingUtils::StringToWstring(parser.get<std::string>("program_name"));
    TargetArguments      = EncodingUtils::SplitWide(TargetExecutableName, L" ");

    if (parser.is_used("--output"))
        WorkDirectory = EncodingUtils::StringToWstring(parser.get<std::string>("--output"));

    if (parser.is_used("--exported"))
        ExportedFunction = EncodingUtils::StringToWstring(parser.get<std::string>("--exported"));

    wcsncpy_s(IchiArguments.WorkDirectory, MAX_PATH, WorkDirectory.c_str(), _TRUNCATE);
    IchiArguments.Unhollow.StopAtWrite  = parser.get<bool>("--stop-at-write");
    IchiArguments.Quiet                 = !parser.get<bool>("--verbose");
    IchiArguments.OnlyPE                = parser.get<bool>("--only-executables");
}