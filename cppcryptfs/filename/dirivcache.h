/*
cppcryptfs : user-mode cryptographic virtual overlay filesystem.

Copyright (C) 2016-2019 Bailey Brown (github.com/bailey27/cppcryptfs)

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

#include "crypt/cryptdefs.h"

#include <unordered_map>
#include <list>

using namespace std;

class DirIvCacheNode {

public:
	wstring m_key;
	unsigned char m_dir_iv[DIR_IV_LEN];
	list<DirIvCacheNode*>::iterator m_list_it;  // holds position in lru list
	ULONGLONG m_timestamp; // milliseconds
	FILETIME m_last_write_time;
	// disallow copying
	DirIvCacheNode(DirIvCacheNode const&) = delete;
	void operator=(DirIvCacheNode const&) = delete;

	DirIvCacheNode();
	virtual ~DirIvCacheNode();
};


#define DIR_IV_CACHE_ENTRIES 100


class DirIvCache {

private:

	ULONGLONG m_ttl;

	unordered_map<wstring, DirIvCacheNode*> m_map;

	list<DirIvCacheNode*> m_lru_list;

	list<DirIvCacheNode*> m_spare_node_list;

	CRITICAL_SECTION m_crit;

	long long m_lookups;
	long long m_hits;
	
	void normalize_key(wstring &key);

	void lock();
	void unlock();

	bool check_node_clean(DirIvCacheNode *node, const wstring& path);
	void update_lru(DirIvCacheNode *node);
public:
	// disallow copying
	DirIvCache(DirIvCache const&) = delete;
	void operator=(DirIvCache const&) = delete;

	DirIvCache();

	virtual ~DirIvCache();

	void SetTTL(int nSecs) { m_ttl = (ULONGLONG)nSecs * 1000; };

	bool lookup(LPCWSTR path, unsigned char *dir_iv);

	bool store(LPCWSTR path, const unsigned char *dir_iv, const FILETIME& last_write_time);

	void remove(LPCWSTR path);

	long long hits() { long long rval; lock(); rval = m_hits; unlock(); return rval; }
	long long lookups() { long long rval; lock(); rval = m_lookups; unlock(); return rval; }
	
};


