#pragma once

#include "stdafx.h"

#include <string>

using namespace std;

bool mountmanager_continue_mounting();

bool DeleteAllRegisteryValues(LPCWSTR regPath, std::wstring& mes);

bool NeverSaveHistory();

