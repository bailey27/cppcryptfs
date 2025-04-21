/*
cppcryptfs : user-mode cryptographic virtual overlay filesystem.

Copyright (C) 2016-2025 Bailey Brown (github.com/bailey27/cppcryptfs)

cppcryptfs is based on the design of gocryptfs (github.com/rfjakob/gocryptfs)

The MIT License (MIT)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#include "pch.h"
#include <string>
#include "server.h"

using namespace std;

// returns ptr into buf where interesting data starts or nullptr on failure
WCHAR *ReadFromNamedPipe(HANDLE hPipe, WCHAR *buf, size_t buflen /* includes null terminator */)
{		
	//_tprintf(TEXT("\nPipe Server: Main thread awaiting client connection on %s\n"), lpszPipename);
	FlushFileBuffers(hPipe);

	if (buflen < 1) {
		return nullptr;
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
		CloseHandle(hPipe);
		return nullptr;
	}

	if (cbBytesRead < 1) {
		CloseHandle(hPipe);
		return nullptr;
	}

	if (buf[cbBytesRead - 1] != '\0') {
		CloseHandle(hPipe);
		return nullptr;
	}

	if (wcslen(buf) < CMD_PIPE_VERSION_LEN) {
		CloseHandle(hPipe);
		return FALSE;
	}
	if (wcsncmp(buf, CMD_PIPE_VERSION_STR, CMD_PIPE_VERSION_LEN) != 0) {
		CloseHandle(hPipe);
		return FALSE;
	}
	
	return buf + CMD_PIPE_VERSION_LEN;
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
			GetNamedPipeName(false),       // pipe name 
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