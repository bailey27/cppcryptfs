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
#include <windows.h>
#include <unordered_map>
#include <string>

using namespace std;

#define CASE_CACHE_ENTRIES 100  // this is directories, not files

class CaseCacheNode {

public:
	wstring m_key; // upercased  path
	wstring m_path; // correct-case path of directory
	unordered_map<wstring, wstring> m_files;  // map of uppercase filenames to correct-case names
	list<CaseCacheNode*>::iterator m_list_it;  // holds position in lru list
	LONGLONG m_timestamp; 
	FILETIME m_filetime;
	// disallow copying
	CaseCacheNode(CaseCacheNode const&) = delete;
	void operator=(CaseCacheNode const&) = delete;
	CaseCacheNode();
	virtual ~CaseCacheNode();
};

// these values returned by lookup()
#define CASE_CACHE_FOUND 0
#define CASE_CACHE_NOT_FOUND 1
#define CASE_CACHE_MISS -2
#define CASE_CACHE_ERROR -3
#define CASE_CACHE_NOTUSED -4

class CryptContext;

class CaseCache
{
private:
	ULONGLONG m_ttl;
	unordered_map<wstring, CaseCacheNode *> m_map;
	list<CaseCacheNode*> m_lru_list;

	list<CaseCacheNode*> m_spare_node_list;

	CRITICAL_SECTION m_crit;

	long long m_lookups;
	long long m_hits;

public:
	CryptContext *m_con;

private:
	void lock();
	void unlock();
	void remove_node(unordered_map<wstring, CaseCacheNode *>::iterator it);
	bool check_node_clean(CaseCacheNode *node);
	void update_lru(CaseCacheNode *node);
public:
	void SetTTL(int nSecs) { m_ttl = (ULONGLONG)nSecs * 1000; };

	bool store(LPCWSTR dirpath, const list<wstring>& files);
	bool store(LPCWSTR dirpath, LPCWSTR file);
	bool store(LPCWSTR filepath);
	int lookup(LPCWSTR path, wstring& result_path, bool force_not_found = false);
	bool remove(LPCWSTR path, LPCWSTR file);
	bool remove(LPCWSTR path);
	bool purge(LPCWSTR path);
	bool rename(LPCWSTR oldpath, LPCWSTR newpath);
	long long hits() { long long rval; lock(); rval = m_hits; unlock(); return rval; }
	long long lookups() { long long rval; lock(); rval = m_lookups; unlock(); return rval; }

	// used to load dir into cache if there is a miss
	bool load_dir(LPCWSTR filepath);

	// disallow copying
	CaseCache(CaseCache const&) = delete;
	void operator=(CaseCache const&) = delete;

	CaseCache();
	virtual ~CaseCache();
};

