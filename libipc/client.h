#pragma once

#include "common.h"

#include <string>

#define SEND_ARGS_STATUS_SUCCESS 0
#define SEND_ARGS_STATUS_ERROR  1
#define SEND_ARGS_STATUS_CANNOT_CONNECT 2

int SendArgsToRunningInstance(LPCWSTR args, std::wstring& result, std::wstring& err);