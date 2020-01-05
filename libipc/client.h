#pragma once

#include "common.h"

#include <string>

bool SendArgsToRunningInstance(LPCWSTR args, std::wstring& result, std::wstring& err);