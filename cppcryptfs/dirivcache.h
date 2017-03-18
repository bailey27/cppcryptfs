/*
cppcryptfs : user-mode cryptographic virtual overlay filesystem.

Copyright (C) 2016-2017 Bailey Brown (github.com/bailey27/cppcryptfs)

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

#include "cryptdefs.h"

#include <unordered_map>
#include <list>


class DirIvCacheNode {

public:
	const std::wstring *m_key;
	unsigned char m_dir_iv[DIR_IV_LEN];
	std::list<DirIvCacheNode*>::iterator m_list_it;  // holds position in lru list
	ULONGLONG m_timestamp; // milliseconds
	FILETIME m_last_write_time;
	DirIvCacheNode();
	virtual ~DirIvCacheNode();
};


#define DIR_IV_CACHE_ENTRIES 100

#define DIR_IV_CACHE_TTL 1000 // milliseconds

class DirIvCache {

private:


	std::unordered_map<std::wstring, DirIvCacheNode*> m_map;

	std::list<DirIvCacheNode*> m_lru_list;

	std::list<DirIvCacheNode*> m_spare_node_list;

	CRITICAL_SECTION m_crit;

	long long m_lookups;
	long long m_hits;
	
	void normalize_key(std::wstring &key);

	void lock();
	void unlock();

	bool check_node_clean(DirIvCacheNode *node, const std::wstring& path);

public:
	DirIvCache();

	virtual ~DirIvCache();

	bool lookup(LPCWSTR path, unsigned char *dir_iv);

	bool store(LPCWSTR path, const unsigned char *dir_iv, const FILETIME& last_write_time);

	void remove(LPCWSTR path);
	
};


