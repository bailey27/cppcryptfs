#pragma once

class RecentItems
{
private:
	CString m_section;
	CString m_base;
	int m_count;
private:
	void AppendIndex(CString& str, int index);
public:
	RecentItems(LPCTSTR section, LPCTSTR base, int count);
	void Add(LPCTSTR item);
	void Populate(CString *items, LPCTSTR initial_default = NULL);
	virtual ~RecentItems(void);
};
