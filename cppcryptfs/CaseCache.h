#pragma once

#include <unordered_map>
#include <string>

#define CASE_CACHE_ENTRIES 100

class CaseCacheNode {

public:
	const std::wstring *m_key; // upercased  path
	std::wstring m_path; // correct-case path of directory
	std::unordered_map<std::wstring, std::wstring> m_files;  // map of uppercase filenames to correct-case names
	std::list<CaseCacheNode*>::iterator m_list_it;  // holds position in lru list
	long long m_timestamp; 
	CaseCacheNode();
	virtual ~CaseCacheNode();
};

// these values returned by lookup()
#define CASE_CACHE_FOUND 0
#define CASE_CACHE_NOT_FOUND 1
#define CASE_CACHE_MISS -2
#define CASE_CACHE_ERROR -3

class CryptContext;

class CaseCache
{
private:
	ULONGLONG m_ttl;
	std::unordered_map<std::wstring, CaseCacheNode *> m_map;
	std::list<CaseCacheNode*> m_lru_list;

	std::list<CaseCacheNode*> m_spare_node_list;

	CRITICAL_SECTION m_crit;

private:
	void lock();
	void unlock();
	void remove_node(std::unordered_map<std::wstring, CaseCacheNode *>::iterator it);
public:
	void SetTTL(int nSecs) { m_ttl = (ULONGLONG)nSecs * 1000; };

	bool store(LPCWSTR dirpath, std::list<std::wstring>& files);
	bool store(LPCWSTR dirpath, LPCWSTR file);
	bool store(LPCWSTR filepath);
	int lookup(LPCWSTR path, std::wstring& result_path);
	bool remove(LPCWSTR path, LPCWSTR file);
	bool remove(LPCWSTR path);
	bool purge(LPCWSTR path);

	// used to load dir into cache if there is a miss
	bool loaddir(CryptContext *con, LPCWSTR filepath);

	CaseCache();
	virtual ~CaseCache();
};

