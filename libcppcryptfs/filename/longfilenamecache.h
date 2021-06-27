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

#include "crypt/cryptdefs.h"

#include <unordered_map>
#include <list>

using namespace std;

#define LFN_CACHE_ENTRIES 5000

// There's no reason to have a TTL on the lfn cache entries because
// each entry maps a 256bit sha hash to some data that it's the hash of.
// So it's impossible for the data to be stale.

#define LFN_CACHE_NOTTL 1

#ifndef LFN_CACHE_NOTTL
#define LFN_CACHE_TTL 3600000
#endif

// this class is used only for reverse mode
// it maps a the base64-encoded sha256 hash in the encrypted long filename to the actual file it corresponds to

class LongFilenameCacheNode {

public:
	wstring m_key;
	wstring  m_path;
	string m_actual_encrypted;
	list<LongFilenameCacheNode*>::iterator m_list_it;  // holds position in lru list
#ifndef LFN_CACHE_NOTTL
	ULONGLONG m_timestap; // milliseconds
#endif
	// disallow copying
	LongFilenameCacheNode(LongFilenameCacheNode const&) = delete;
	void operator=(LongFilenameCacheNode const&) = delete;

	LongFilenameCacheNode();
	virtual ~LongFilenameCacheNode();
};



class LongFilenameCache {

private:


	unordered_map<wstring, LongFilenameCacheNode*> m_map;

	list<LongFilenameCacheNode*> m_lru_list;

	list<LongFilenameCacheNode*> m_spare_node_list;

	CRITICAL_SECTION m_crit;

	long long m_lookups;
	long long m_hits;

	void lock();
	void unlock();

	bool check_node_clean(LongFilenameCacheNode *node, const wstring& path);

public:

	// disallow copying
	LongFilenameCache(LongFilenameCache const&) = delete;
	void operator=(LongFilenameCache const&) = delete;

	LongFilenameCache();

	virtual ~LongFilenameCache();

	bool lookup(LPCWSTR base64_hash, wstring *path, string *actual_encrypted);

	bool store_if_not_there(LPCWSTR base64_hash, LPCWSTR path, const char *actual_encrypted);

	void remove(LPCWSTR base64_hash);
	
	long long hits() { long long rval; lock(); rval = m_hits; unlock(); return rval; }
	long long lookups() { long long rval; lock(); rval = m_lookups; unlock(); return rval; }
};


