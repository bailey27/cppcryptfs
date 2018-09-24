/*
cppcryptfs : user-mode cryptographic virtual overlay filesystem.

Copyright (C) 2016-2018 Bailey Brown (github.com/bailey27/cppcryptfs)

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

#include "stdafx.h"
#include "recentitems.h"
#include "cppcryptfs.h"
#include "cryptdefaults.h"
#include "util/util.h"

RecentItems::RecentItems(LPCTSTR section, LPCTSTR base, int count)
{
	m_section = section;
	m_base = base;
	m_count = count;
}

RecentItems::~RecentItems(void)
{
}

void
RecentItems::AppendIndex(CString& str, int index)
{
	TCHAR buf[16];
	swprintf_s(buf, L"%d", index+1);
	str = m_base;
	str += buf;
}

void
RecentItems::Populate(CString *items, LPCTSTR initial_default)
{
	int i;
	CString itemname;

	

	if (!initial_default)
		initial_default = TEXT("");

	for (i = 0; i < m_count; i++) {
		AppendIndex(itemname, i);
		
		items[i] = theApp.GetProfileString(m_section, itemname,
			i == 0 ? initial_default : TEXT(""));
	}
}

void
RecentItems::Add(LPCTSTR item)
{
	int i;

	bool bSave = !NeverSaveHistory();

	CString *lastitems = new CString[m_count];

	ASSERT(lastitems);
	if (!lastitems)
		return;

	Populate(lastitems);

	CString itemname;
    
	int index = m_count-1;

	for (i = 0; i < m_count; i++) {
		if (!lstrcmpi(item, lastitems[i])) {
			index = i;
			break;
		}
	}	
	
	for (i = index; i >= 1; i--) {
		AppendIndex(itemname, i);
		if (bSave) {
			theApp.WriteProfileStringW(m_section, itemname, lastitems[i - 1]);
		}
	}

	AppendIndex(itemname, 0);
	if (bSave) {
		theApp.WriteProfileString(m_section, itemname, item);
	}

	delete[] lastitems;
}
