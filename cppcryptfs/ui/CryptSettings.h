#pragma once
/*
cppcryptfs : user-mode cryptographic virtual overlay filesystem.

Copyright (C) 2016-2023 Bailey Brown (github.com/bailey27/cppcryptfs)

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

#include <string>
#include <unordered_map>

struct CryptMountOptions;

struct CryptSettingConsts {
	std::wstring regval_name;
	int default;
	int recommended;
	CryptSettingConsts() : regval_name(L""), default(0), recommended(0) {}
	CryptSettingConsts(const wchar_t* name, int default, int recommended) :
		regval_name((name)), default(default), recommended(recommended) {}
};


class CryptSettings {
private:
	
	CryptSettings();

	std::unordered_map<enum CryptSettingsRegistryValuesKeys, CryptSettingConsts> m_settings_registry_map;
public:	

	static CryptSettings& getInstance();

	bool GetSettingDefault(enum CryptSettingsRegistryValuesKeys key, int& default);
	bool GetSettingRecommended(enum CryptSettingsRegistryValuesKeys key, int& recommended);
	bool GetSettingDefault(enum CryptSettingsRegistryValuesKeys key, bool& default);
	bool GetSettingRecommended(enum CryptSettingsRegistryValuesKeys key, bool& recommended);
	bool GetSettingCurrent(enum CryptSettingsRegistryValuesKeys key, bool& cur);
	bool GetSettingCurrent(enum CryptSettingsRegistryValuesKeys key, int& cur);

	bool SaveSetting(enum CryptSettingsRegistryValuesKeys key, int val);

	void GetSettings(CryptMountOptions& opts);


	// disallow copying and moving
	CryptSettings(CryptSettings const&) = delete;
	void operator=(CryptSettings const&) = delete;

	CryptSettings(CryptSettings const&&) = delete;
	void operator=(CryptSettings const&&) = delete;

};