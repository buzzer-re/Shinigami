#include "ShinigamiArguments.h"


ShinigamiArguments::ShinigamiArguments()
{
    wchar_t cwd[MAX_PATH];
    GetCurrentDirectoryW(MAX_PATH, cwd);
    WorkDirectory = cwd;
}

void ShinigamiArguments::ParseArguments(int argc, char* argv[], const char* ProgamName) {
    argparse::ArgumentParser parser(ProgamName);
    parser.add_argument("program_name")
        .help("Name of the program to execute");
    parser.add_argument("--output", "-o")
        .help("Directory to dump artefacts");

    try {
        parser.parse_args(argc, argv);
    }
    catch (const std::runtime_error& e) {
        throw std::runtime_error(std::string("Error parsing arguments: ") + e.what());
    }

    TargetExecutableName = EncodingUtils::StringToWstring(parser.get<std::string>("program_name"));

    if (parser.present("--output"))
        WorkDirectory = EncodingUtils::StringToWstring(parser.get<std::string>("--output"));


    wcsncpy_s(IchiArguments.WorkDirectory, MAX_PATH, WorkDirectory.c_str(), _TRUNCATE);
}