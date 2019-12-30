#pragma once

#include <string>

#define CMD_NAMED_PIPE L"\\\\.\\pipe\\cppcryptfs_cmd"

#define CMD_NAMED_PIPE_BUFSIZE 2048 // max command line length

#define CMD_PIPE_SUCCESS 0
#define CMD_PIPE_ERROR   1
#define CMD_PIPE_RESPONSE_LENGTH 7
#define CMD_PIPE_SUCCESS_STR L"SUCCESS"
#define CMD_PIPE_ERROR_STR   L"ERROR  " // pad to 7 characters
 

int ReadFromNamedPipe(HANDLE hPipe, std::wstring& str);

int WriteToNamedPipe(HANDLE hPipe, const std::wstring& str);

bool StartNamedPipeServer();