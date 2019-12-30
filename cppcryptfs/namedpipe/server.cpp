#include <windows.h>
#include <string>
#include "server.h"

using namespace std;

int ReadFromNamedPipe(HANDLE hPipe, wstring& str)
{		
	//_tprintf(TEXT("\nPipe Server: Main thread awaiting client connection on %s\n"), lpszPipename);
	FlushFileBuffers(hPipe);

	DWORD cbBytesRead = 0;

	str = L"";
	
	WCHAR buf[CMD_NAMED_PIPE_BUFSIZE];

	auto fSuccess = ReadFile(
		hPipe,        // handle to pipe 
		buf,    // buffer to receive data 
		CMD_NAMED_PIPE_BUFSIZE * sizeof(WCHAR), // size of buffer 
		&cbBytesRead, // number of bytes read 
		NULL);        // not overlapped I/O 

	if (!fSuccess) {
		DWORD lastErr = GetLastError();
		return -1;
	}

	if (cbBytesRead == 0) {
		return 0;
	}

	str = std::wstring(buf, cbBytesRead);
	
	return static_cast<int>(str.length());
}

int WriteToNamedPipe(HANDLE hPipe, const wstring& str)
{
	DWORD cbWritten = 0;
	auto fSuccess = WriteFile(
		hPipe,                  // pipe handle 
		str.c_str(),            // message 
		static_cast<DWORD>((str.length()+1)*sizeof(wchar_t)), // message length 
		&cbWritten,             // bytes written 
		NULL);                  // not overlapped

	if (!fSuccess)
		return -1;

	return cbWritten;
}

