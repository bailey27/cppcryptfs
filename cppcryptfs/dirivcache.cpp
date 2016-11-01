/*
cppcryptfs : user-mode cryptographic virtual overlay filesystem.

Copyright (C) 2016 - Bailey Brown (github.com/bailey27/cppcryptfs)

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

#include "dirivcache.h"

#include "fileutil.h"

/* 
	Thid file implements a cache that replaces the least-recently-used (LRU)
	item when a new item is inserted and the cache is full.

	The node pointers are kept in both a std::unordered_map and a std::list

	The map is for lookups, and the list is for doing the LRU replacement.
*/

DirIvCacheNode::DirIvCacheNode()
{
	m_key = NULL;
	m_timestap = 0;
}

DirIvCacheNode::~DirIvCacheNode()
{
}



DirIvCache::DirIvCache()
{

	m_lookups = 0;
	m_hits = 0;

	m_map.reserve(DIR_IV_CACHE_ENTRIES);

	InitializeCriticalSection(&m_crit);
}

DirIvCache::~DirIvCache()
{

	for (auto it = m_lru_list.begin(); it != m_lru_list.end(); it++) {
		DirIvCacheNode *node = *it;
		delete node;
	}

	for (auto it = m_spare_node_list.begin(); it != m_spare_node_list.end(); it++) {
		DirIvCacheNode *node = *it;
		delete node;
	}
}

void DirIvCache::normalize_key(std::wstring& key)
{
	if (key.size() > 0 && key[key.size() - 1] != '\\') {
		key.push_back('\\');
	}
}

void DirIvCache::lock()
{
	EnterCriticalSection(&m_crit);
}

void DirIvCache::unlock()
{
	LeaveCriticalSection(&m_crit);
}



bool DirIvCache::lookup(LPCWSTR path, unsigned char *dir_iv)
{
	std::wstring key = path;

	bool found;

	normalize_key(key);

	lock();

	m_lookups++;

	auto it = m_map.find(key);

	if (it != m_map.end()) {

		DirIvCacheNode *node = it->second;

		// If a node is older than the TTL (currently 1 second), then remove it, add it to the spare node list, and pretend it wasn't there.
		// This is done in order to have some sort of coherency if other systems are modifying a synced filesystem.

		if (GetTickCount64() - node->m_timestap < DIR_IV_CACHE_TTL) {

			// entry is less than TLL old, use it

			memcpy(dir_iv, node->m_dir_iv, DIR_IV_LEN);

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

			// The entry is expired. Remove it, add it to the spare list, and return a miss.

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
		DbgPrint(L"DirIvCache: %I64d lookups, %I64d hits, %I64d misses, hit ratio %0.2f%%\n", m_lookups, m_hits, m_lookups - m_hits, ratio*100);
	}

	unlock();

	return found;
}


bool DirIvCache::store(LPCWSTR path, const unsigned char *dir_iv)
{

	bool rval = true;

	std::wstring key = path;

	normalize_key(key);

	lock();

	try {

		// see if it's already there
		auto mp = m_map.emplace(key, (DirIvCacheNode*)NULL);		

		if (mp.second) {

			DirIvCacheNode *node = NULL;

			// if it isn't, then see if the cache is full
			
			// if so, remove oldest entry (from tail of linked list)
			
			if (m_map.size() >= DIR_IV_CACHE_ENTRIES) {
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
					node = new DirIvCacheNode;
				}
			}

			mp.first->second = node;

			node->m_key = &mp.first->first;
			memcpy(node->m_dir_iv, dir_iv, DIR_IV_LEN);
			node->m_timestap = GetTickCount64();
			node->m_list_it = m_lru_list.insert(m_lru_list.begin(), node);
			
		} else {
			// copy dir_iv to node at that path (key)
			memcpy(mp.first->second->m_dir_iv, dir_iv, DIR_IV_LEN);
		}
		

	} catch (...) {
		rval = false;
	}
   
	unlock();

	return rval;
}

void DirIvCache::remove(LPCWSTR path)
{
	std::wstring key = path;

	normalize_key(key);

	lock();

	auto it = m_map.find(key);

	if (it != m_map.end()) {

		DirIvCacheNode *node = it->second;

		m_map.erase(it);

		m_lru_list.erase(node->m_list_it);

		m_spare_node_list.push_back(node);
	}

	unlock();
}
