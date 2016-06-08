#include "stdafx.h"
#include "recentitems.h"
#include "cppcryptfs.h"

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
	wsprintf(buf, TEXT("%d"), index+1);
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
		theApp.WriteProfileStringW(m_section, itemname, lastitems[i-1]);	
	}

	AppendIndex(itemname, 0);
	theApp.WriteProfileString(m_section, itemname, item);

	delete[] lastitems;
}
