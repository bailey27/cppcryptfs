/*
cppcryptfs : user-mode cryptographic virtual overlay filesystem.

Copyright (C) 2016-2021 Bailey Brown (github.com/bailey27/cppcryptfs)

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

#pragma once

#include "stdafx.h"
#include <functional>
#include "cppcryptfs.h"
#include "CryptPropertyPage.h"
#include "cryptdefaults.h"
#include "CryptSettings.h"


class CryptSetting
{
public:
	typedef enum { Default, Recommended, Current, Changed } SetType;

	virtual void Set(CryptSetting::SetType set_type, bool save = true) = 0;
protected:	
	const enum CryptSettingsRegistryValuesKeys m_key;	
	
		
public:
	CryptSetting(enum CryptSettingsRegistryValuesKeys key) : m_key(key) {}
	virtual ~CryptSetting() = default;
};

class CryptSettingControl : public CryptSetting 
{
public:	
	
protected:
	CCryptPropertyPage& m_dlg;
	const int m_id;
	
public:
	CryptSettingControl(CCryptPropertyPage& dlg, int id, enum CryptSettingsRegistryValuesKeys key) : CryptSetting(key), m_dlg(dlg), m_id(id) {}
	virtual ~CryptSettingControl() = default;
};

class CryptCheckBoxSetting : public CryptSettingControl {
public:
	CryptCheckBoxSetting(CCryptPropertyPage& dlg, int id,  enum CryptSettingsRegistryValuesKeys key)
		: CryptSettingControl(dlg, id, key) {}
	virtual ~CryptCheckBoxSetting() = default;

	virtual void Set(SetType set_type, bool save = true) override;
};

class CryptComboBoxSetting : public CryptSettingControl {

protected:
	 std::function<void(CComboBox*, int val)> m_set_from_registry;
	 std::function<bool(CComboBox*, int& val)> m_get_from_control;
public:
	CryptComboBoxSetting(CCryptPropertyPage& dlg, int id, CryptSettingsRegistryValuesKeys key, std::function<void(CComboBox*, int val)> set_from_registry, std::function<bool(CComboBox*, int& val)> get_from_control)
		: CryptSettingControl(dlg, id, key),  m_set_from_registry(set_from_registry), m_get_from_control(get_from_control) {}
	virtual ~CryptComboBoxSetting() = default;

	virtual void Set(SetType set_type, bool save = true) override;
};