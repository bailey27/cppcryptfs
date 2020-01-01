#include "pch.h"
#include <string>
#include "server.h"

using namespace std;

int ReadFromNamedPipe(HANDLE hPipe, WCHAR *buf, size_t buflen /* includes null terminator */)
{		
	//_tprintf(TEXT("\nPipe Server: Main thread awaiting client connection on %s\n"), lpszPipename);
	FlushFileBuffers(hPipe);

	if (buflen < 1) {
		return 0;
	}

	*buf = '\0';

	DWORD cbBytesRead = 0;

	auto fSuccess = ReadFile(
		hPipe,        // handle to pipe 
		buf,    // buffer to receive data 
		static_cast<DWORD>(buflen) * sizeof(buf[0]), // size of buffer 
		&cbBytesRead, // number of bytes read 
		NULL);        // not overlapped I/O 

	if (!fSuccess) {
		DWORD lastErr = GetLastError();
		return -1;
	}

	if (cbBytesRead < 1) {
		return 0;
	}

	if (buf[cbBytesRead - 1] != '\0') {
		return -1;
	}
	
	return cbBytesRead - 1;
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

DWORD WINAPI NamedPipeServerThreadProc(PVOID lpvParam)
{
	//_tprintf(TEXT("\nPipe Server: Main thread awaiting client connection on %s\n"), lpszPipename);


	while (true) {
		// Wait for the client to connect; if it succeeds, 
		// the function returns a nonzero value. If the function
		// returns zero, GetLastError returns ERROR_PIPE_CONNECTED. 

		auto hPipe = CreateNamedPipe(
			CMD_NAMED_PIPE,             // pipe name 
			PIPE_ACCESS_DUPLEX,       // read/write access 
			PIPE_TYPE_MESSAGE |       // message type pipe 
			PIPE_READMODE_MESSAGE |   // message-read mode 
			PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,  // blocking mode, local only 
			PIPE_UNLIMITED_INSTANCES, // max. instances  
			CMD_NAMED_PIPE_BUFSIZE,   // output buffer size 
			CMD_NAMED_PIPE_BUFSIZE,   // input buffer size 
			0,                        // client time-out 
			NULL);                    // default security attribute 

		if (hPipe == INVALID_HANDLE_VALUE)
			return 1;

		auto fConnected = ConnectNamedPipe(hPipe, NULL) ?
			TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);

		if (fConnected) {
			auto con = reinterpret_cast<NamedPipeServerContext*>(lpvParam);
			con->callback(con->context, hPipe);
		} else {
			// The client could not connect, so close the pipe. 
			CloseHandle(hPipe);
		}
	}

	return 0;
}