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

#include "stdafx.h"

#include <windows.h>

#include "LongFilenameCache.h"

#include "fileutil.h"

/* 
	Thid file implements a cache that replaces the least-recently-used (LRU)
	item when a new item is inserted and the cache is full.

	The node pointers are kept in both a std::unordered_map and a std::list

	The map is for lookups, and the list is for doing the LRU replacement.
*/

LongFilenameCacheNode::LongFilenameCacheNode()
{
	m_key = NULL;

#ifndef LFN_CACHE_NOTTL
	m_timestap = 0;
#endif
}

LongFilenameCacheNode::~LongFilenameCacheNode()
{
}



LongFilenameCache::LongFilenameCache()
{

	m_lookups = 0;
	m_hits = 0;

	m_map.reserve(LFN_CACHE_ENTRIES);

	InitializeCriticalSection(&m_crit);
}

LongFilenameCache::~LongFilenameCache()
{

	for (auto it = m_lru_list.begin(); it != m_lru_list.end(); it++) {
		LongFilenameCacheNode *node = *it;
		delete node;
	}

	for (auto it = m_spare_node_list.begin(); it != m_spare_node_list.end(); it++) {
		LongFilenameCacheNode *node = *it;
		delete node;
	}
}


void LongFilenameCache::lock()
{
	EnterCriticalSection(&m_crit);
}

void LongFilenameCache::unlock()
{
	LeaveCriticalSection(&m_crit);
}

bool LongFilenameCache::check_node_clean(LongFilenameCacheNode *node, const std::wstring& path)
{
#ifndef LFN_CACHE_NOTTL

	if (GetTickCount64() - node->m_timestap < LFN_CACHE_TTL)
		return true;

	return false;
#else
	return true;
#endif
}



bool LongFilenameCache::lookup(LPCWSTR base64_hash, std::wstring *path, std::string *actual_encrypted)
{

	const WCHAR *key = base64_hash;

	bool found;

	lock();

	m_lookups++;

	auto it = m_map.find(key);

	if (it != m_map.end()) {

		LongFilenameCacheNode *node = it->second;

		if (check_node_clean(node, key)) {

			// The entry not stale, so use it.

			if (path)
				*path = node->m_path;
			if (actual_encrypted)
				*actual_encrypted = node->m_actual_encrypted;

			// if node isn't already at front of list, remove
			// it from wherever it was and put it at the front

			if (node->m_list_it != m_lru_list.begin()) {
				m_lru_list.erase(node->m_list_it);
				m_lru_list.push_front(node);
				node->m_list_it = m_lru_list.begin();
			}
			found = true;
			m_hits++;

		} else {

			// The entry is no longer valid. Remove it, add it to the spare list, and return a miss.

			m_map.erase(it);

			m_lru_list.erase(node->m_list_it);

			m_spare_node_list.push_front(node);

			found = false;
		}
	} else {
		found = false;
	}

	if (m_lookups && (m_lookups % 1024 == 0)) {
		double ratio = (double)m_hits / (double)m_lookups;
		DbgPrint(L"LongFilenameCache: %I64d lookups, %I64d hits, %I64d misses, hit ratio %0.2f%%\n", m_lookups, m_hits, m_lookups - m_hits, ratio*100);
	}

	unlock();

	return found;
}


bool LongFilenameCache::store_if_not_there(LPCWSTR base64_hash, LPCWSTR path, const char *actual_encrypted)
{

	bool rval = true;

	const WCHAR *key = base64_hash;

	lock();

	try {

		// see if it's already there.  If it isn't, inser it.
		
		// If it is already there THEN DO NOTHING

		auto mp = m_map.emplace(key, (LongFilenameCacheNode*)NULL);		

		if (mp.second) {

			LongFilenameCacheNode *node = NULL;

			// if it isn't, then see if the cache is full
			
			// if so, remove oldest entry (from tail of linked list)
			
			if (m_map.size() >= LFN_CACHE_ENTRIES) {
				node = m_lru_list.back();
				m_lru_list.pop_back();
				m_map.erase(*node->m_key);
			}

			// re-use node if we removed one, otherwise get one from spare list, otherwise make a new one

			if (!node) {
				if (!m_spare_node_list.empty()) {
					node = m_spare_node_list.front();
					m_spare_node_list.pop_front();
				} else {
					node = new LongFilenameCacheNode;
				}
			}

			mp.first->second = node;

			node->m_key = &mp.first->first;
			node->m_path = path;
			node->m_actual_encrypted = actual_encrypted;
#ifndef LFN_CACHE_NOTTL
			node->m_timestap = GetTickCount64();
#endif
			node->m_list_it = m_lru_list.insert(m_lru_list.begin(), node);
			
		}

	} catch (...) {
		rval = false;
	}
   
	unlock();

	return rval;
}

void LongFilenameCache::remove(LPCWSTR base64_hash)
{
	const WCHAR *key = base64_hash;

	lock();

	auto it = m_map.find(key);

	if (it != m_map.end()) {

		LongFilenameCacheNode *node = it->second;

		m_map.erase(it);

		m_lru_list.erase(node->m_list_it);

		m_spare_node_list.push_back(node);
	}

	unlock();
}
