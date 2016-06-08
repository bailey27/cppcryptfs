#pragma once

#include "cryptdefs.h"

#include <unordered_map>
#include <list>


class DirIvCacheNode {

public:
	std::wstring m_key;
	unsigned char m_dir_iv[DIR_IV_LEN];
	std::list<DirIvCacheNode*>::iterator m_list_it;  // holds position in lru list
	DirIvCacheNode();
	virtual ~DirIvCacheNode();
};


#define DIR_IV_CACHE_ENTRIES 200

class DirIvCache {

private:


	std::unordered_map<std::wstring, DirIvCacheNode*> m_map;

	std::list<DirIvCacheNode*> m_lru_list;

	CRITICAL_SECTION m_crit;

	long long m_lookups;
	long long m_hits;
	
	void normalize_key(std::wstring &key);

public:
	DirIvCache();

	virtual ~DirIvCache();

	bool lookup(LPCWSTR path, unsigned char *dir_iv);

	bool store(LPCWSTR path, const unsigned char *dir_iv);

	void remove(LPCWSTR path);


};


