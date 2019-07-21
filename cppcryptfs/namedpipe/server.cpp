#include "stdafx.h"
#include <string>
#include "server.h"

#include "cppcryptfs.h"

#if 0
static DWORD WINAPI HandleClientThreadProc(PVOID lpvParam)
{
	
		
	//_tprintf(TEXT("\nPipe Server: Main thread awaiting client connection on %s\n"), lpszPipename);
	auto hPipe = (HANDLE)lpvParam;

	DWORD cbBytesRead = 0;
	
	WCHAR buf[CMD_NAMED_PIPE_BUFSIZE];
	auto fSuccess = ReadFile(
		hPipe,        // handle to pipe 
		buf,    // buffer to receive data 
		CMD_NAMED_PIPE_BUFSIZE * sizeof(WCHAR), // size of buffer 
		&cbBytesRead, // number of bytes read 
		NULL);        // not overlapped I/O 
	if (!fSuccess || cbBytesRead == 0) {
		return 1;
	}
	std::wstring args = std::wstring(buf, cbBytesRead);
	theApp.SendCmdArgsToSelf(hPipe);
	
	FlushFileBuffers(hPipe);
	DisconnectNamedPipe(hPipe);
	CloseHandle(hPipe);
	
	return 0;
}
#endif

static DWORD WINAPI ServerThreadProc(PVOID lpvParam)
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
			theApp.SendCmdArgsToSelf(hPipe);
		} else {
			// The client could not connect, so close the pipe. 
			CloseHandle(hPipe);
		}
	}

	return 0;
}


bool StartNamedPipeServer()
{
	auto hThread = CreateThread(NULL, 0, ServerThreadProc, NULL, 0, NULL);

	if (hThread != NULL)
		CloseHandle(hThread);

	return hThread != NULL;
}