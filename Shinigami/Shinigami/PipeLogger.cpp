#include "PipeLogger.h"

using namespace PipeLogger;


//
// Create a named pipe and a connection handling thread
//
BOOL PipeLogger::InitPipe()
{
	hPipe = CreateNamedPipe(PIPE_NAME,
			PIPE_ACCESS_DUPLEX, 
			PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, 
			PIPE_UNLIMITED_INSTANCES, 
			sizeof(LogMsg),
			sizeof(LogMsg),
			0, 
			NULL);


	if (hPipe == INVALID_HANDLE_VALUE) return false;


	hThread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)LoggerThread, hPipe, NULL, NULL);

	if (hThread == INVALID_HANDLE_VALUE)
	{
		CloseHandle(hPipe);
		return false;
	}

	return true;
}

VOID PipeLogger::ClosePipe()
{
	if (hPipe != INVALID_HANDLE_VALUE)
		CloseHandle(hPipe);
	
	if (hThread != INVALID_HANDLE_VALUE)
		CloseHandle(hThread);
}


VOID PipeLogger::LoggerThread(ULONG_PTR* params)
{
	HANDLE hPipe = reinterpret_cast<HANDLE>(params);
	BYTE* data = new BYTE[sizeof(LogMsg)];
	DWORD dwRead;
	LogMsg* msg;
	bool first = true;
	while (true)
	{
		if (ReadFile(hPipe, data, sizeof(LogMsg), &dwRead, NULL))
		{
			msg = reinterpret_cast<LogMsg*>(data);

			if (msg->MessageType == EXITING) break;
			
			if (first)
			{
				Logger::LogInfo(L"Connected with the remote process! processing logs...");
				first = false;
			}

			switch (msg->MessageType)
			{
				case EXITING: break;
				case INFO_LOG:
					Logger::LogInfo(msg->message);
					break;
			}
		}
	}

	
	Logger::LogInfo(L"Closing thread..");
	delete[] data;
	return VOID();
}

VOID Logger::LogInfo(const wchar_t* message, ...)
{
	va_list args;
	va_start(args, message);

	fputws(L"[+] Shinigami Info: ", stdout);
	vfwprintf(stdout, message, args);
	fputws(L" [+] \n", stdout);

	va_end(args);
}
