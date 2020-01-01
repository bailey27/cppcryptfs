#pragma once

#include <string>

#include "common.h"

struct NamedPipeServerContext {
	void* context;
	void (*callback)(void *ctx, HANDLE hPipe);
};

int ReadFromNamedPipe(HANDLE hPipe, WCHAR *buf, size_t buflen /* includes null terminator */);

int WriteToNamedPipe(HANDLE hPipe, const std::wstring& str);

DWORD WINAPI NamedPipeServerThreadProc(PVOID lpvParam);

bool StartNamedPipeServer();