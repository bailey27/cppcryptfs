#pragma once

#include <unordered_map>
#include <string>

class CaseCacheNode {

public:
	const std::wstring *m_path;
	std::list<CaseCacheNode*>::iterator m_list_it;  // holds position in lru list
	CaseCacheNode();
	virtual ~CaseCacheNode();
};

class CaseCache
{
private:
	int m_max_entries;
	std::unordered_map<std::wstring, CaseCacheNode *> m_map;
	std::list<CaseCacheNode*> m_lru_list;

	std::list<CaseCacheNode*> m_spare_node_list;

	CRITICAL_SECTION m_crit;

private:
	void lock();
	void unlock();
public:

	bool store(LPCWSTR path);
	bool lookup(LPCWSTR path, std::wstring& result_path);
	bool purge(LPCWSTR path);

	CaseCache();
	virtual ~CaseCache();
};

