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
#include "CaseCache.h"
#include "util.h"
#include "fileutil.h"
#include "cryptcontext.h"
#include "cryptfilename.h"

CaseCacheNode::CaseCacheNode() 
{
	m_timestamp = 0;
	m_key = NULL;

	memset(&m_filetime, 0, sizeof(m_filetime));
}

CaseCacheNode::~CaseCacheNode() 
{

}

CaseCache::CaseCache()
{
	m_ttl = 0;

	m_map.reserve(CASE_CACHE_ENTRIES);

	InitializeCriticalSection(&m_crit);
}


CaseCache::~CaseCache()
{
	for (auto it = m_lru_list.begin(); it != m_lru_list.end(); it++) {
		CaseCacheNode *node = *it;
		delete node;
	}

	for (auto it = m_spare_node_list.begin(); it != m_spare_node_list.end(); it++) {
		CaseCacheNode *node = *it;
		delete node;
	}
}

void CaseCache::lock()
{
	EnterCriticalSection(&m_crit);
}

void CaseCache::unlock()
{
	LeaveCriticalSection(&m_crit);
}

bool CaseCache::check_node_clean(CaseCacheNode *node)
{

	if (!m_ttl || (GetTickCount64() - node->m_timestamp < m_ttl))
		return true;

	std::wstring enc_path;

	if (!encrypt_path(m_con, node->m_path.c_str(), enc_path, NULL)) 
		return false;

	HANDLE hFile = CreateFile(enc_path.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
		OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);

	if (hFile == INVALID_HANDLE_VALUE)
		return false;

	FILETIME LastWriteTime;

	BOOL bResult = GetFileTime(hFile, NULL, NULL, &LastWriteTime);

	CloseHandle(hFile);

	if (!bResult)
		return false;

	bResult = CompareFileTime(&node->m_filetime, &LastWriteTime) >= 0;

	if (bResult)
		node->m_timestamp = GetTickCount64();
	
	if (bResult)
		return true;
	else
		return false;
}

void CaseCache::update_lru(CaseCacheNode *node)
{
	// if node isn't already at front of list, remove
	// it from wherever it was and put it at the front

	if (node->m_list_it != m_lru_list.begin()) {
		m_lru_list.erase(node->m_list_it);
		m_lru_list.push_front(node);
		node->m_list_it = m_lru_list.begin();
	}
}

bool CaseCache::store(LPCWSTR dirpath, std::list<std::wstring>& files)
{
	bool bRet = true;

	std::wstring key;

	if (!touppercase(dirpath, key))
		return false;

	lock();

	try {
		// see if it's already there
		auto mp = m_map.emplace(key, (CaseCacheNode*)NULL);		

		if (mp.second) {

			CaseCacheNode *node = NULL;

			// if it isn't, then see if the cache is full

			// if so, remove oldest entry (from tail of linked list)

			if (m_map.size() >= CASE_CACHE_ENTRIES) {
				node = m_lru_list.back();
				m_lru_list.pop_back();
				m_map.erase(*node->m_key);
				node->m_files.clear();
			}

			// re-use node if we removed one, otherwise get one from spare list, otherwise make a new one

			if (!node) {
				if (!m_spare_node_list.empty()) {
					node = m_spare_node_list.front();
					m_spare_node_list.pop_front();
				} else {
					node = new CaseCacheNode;
				}
			}

			mp.first->second = node;

			node->m_key = &mp.first->first;
			node->m_path = dirpath;
			std::wstring ucfile;
			for (auto it = files.begin(); it != files.end(); it++) {
				if (!touppercase(it->c_str(), ucfile)) {
					DbgPrint(L"CaseCache.cpp thread %u exception at line %d\n",  GetCurrentThreadId(), __LINE__);
					throw(-1);
				}
				node->m_files.insert(std::make_pair(ucfile, *it));
			}
			node->m_timestamp = GetTickCount64();
			GetSystemTimeAsFileTime(&node->m_filetime);
			node->m_list_it = m_lru_list.insert(m_lru_list.begin(), node);

		} else {
			
			mp.first->second->m_files.clear();
			std::wstring ucfile;
			for (auto it = files.begin(); it != files.end(); it++) {
				if (!touppercase(it->c_str(), ucfile)) {
					DbgPrint(L"CaseCache.cpp thread %u exception at line %d\n",  GetCurrentThreadId(), __LINE__);
					throw(-1);
				}
				mp.first->second->m_files.insert(std::make_pair(ucfile, *it));
			}
			mp.first->second->m_path = dirpath;
			mp.first->second->m_timestamp = GetTickCount64();
			GetSystemTimeAsFileTime(&mp.first->second->m_filetime);

			update_lru(mp.first->second);
		}
	} catch(...) {
		bRet = false;
	}

	unlock();

	return bRet;
}

bool CaseCache::store(LPCWSTR dirpath, LPCWSTR file)
{
	bool bRet = true;

	std::wstring key;

	if (!touppercase(dirpath, key))
		return false;

	lock();

	try {

		auto it = m_map.find(key);

		if (it == m_map.end()) {
			DbgPrint(L"CaseCache.cpp thread %u exception at line %d\n",  GetCurrentThreadId(), __LINE__);
			throw(-1);
		}

		CaseCacheNode *node = it->second;

		std::wstring ucfile;

		if (!touppercase(file, ucfile)) {
			DbgPrint(L"CaseCache.cpp thread %u exception at line %d\n",  GetCurrentThreadId(), __LINE__);
			throw(-1);
		}

		node->m_files.insert_or_assign(ucfile, file);

	} catch (...) {
		bRet = false;
	}

	unlock();

	return bRet;
}

bool CaseCache::store(LPCWSTR filepath)
{

	std::wstring dir;
	std::wstring file;

	if (!get_dir_and_file_from_path(filepath, &dir, &file))
		return false;

	return store(dir.c_str(), file.c_str());
}


int CaseCache::lookup(LPCWSTR path, std::wstring& result_path)
{

	if (!wcscmp(path, L"\\") || !wcscmp(path, L"\\*")) {
		result_path = path;
		return CASE_CACHE_FOUND;
	}

	int ret;

	std::wstring dir;
	std::wstring file;

	if (!get_dir_and_file_from_path(path, &dir, &file))
		return false;

	std::wstring ucdir;
	std::wstring ucfile;

	if (!touppercase(dir.c_str(), ucdir))
		return false;

	if (!touppercase(file.c_str(), ucfile))
		return false;

	lock();

	try {

		auto it = m_map.find(ucdir);

		if (it == m_map.end()) {
			ret = CASE_CACHE_MISS;
		} else {

			CaseCacheNode *node = it->second;

			if (!check_node_clean(node)) {
				remove_node(it);
				ret = CASE_CACHE_MISS;
			} else {

				update_lru(node);

				auto nit = node->m_files.find(ucfile);

				bool isRoot = wcscmp(node->m_path.c_str(), L"\\") == 0;

				if (nit != node->m_files.end()) {
					ret = CASE_CACHE_FOUND;
					result_path = node->m_path + (isRoot ? L"" : L"\\") + nit->second;
				} else {
					ret = CASE_CACHE_NOT_FOUND;
					result_path = node->m_path + (isRoot ? L"" : L"\\") + file;
				}
			}
		}
	
	} catch (int err) {
		ret = err;
	} catch (...) {
		ret = CASE_CACHE_ERROR;
	}
	
	unlock();

	return ret;
}

bool CaseCache::remove(LPCWSTR path, LPCWSTR file)
{
	std::wstring ucdir;
	std::wstring ucfile;

	if (!touppercase(path, ucdir))
		return false;

	if (!touppercase(file, ucfile))
		return false;

	bool bRet = true;

	lock();

	try {

		auto it = m_map.find(ucdir);

		if (it == m_map.end()) {
			DbgPrint(L"CaseCache.cpp thread %u exception at line %d\n",  GetCurrentThreadId(), __LINE__);
			throw(-1);
		}

		CaseCacheNode *node = it->second;

		auto nit = node->m_files.find(ucfile);

		if (nit == node->m_files.end()) {
			DbgPrint(L"CaseCache.cpp thread %u exception at line %d\n",  GetCurrentThreadId(), __LINE__);
			throw(-1);
		}

		node->m_files.erase(nit);
	
	} catch (...) {
		bRet = false;
	}

	unlock();

	return bRet;
}

bool CaseCache::remove(LPCWSTR path)
{
	std::wstring dir;
	std::wstring file;

	if (!get_dir_and_file_from_path(path, &dir, &file))
		return false;

	return remove(dir.c_str(), file.c_str());
}

void CaseCache::remove_node(std::unordered_map<std::wstring, CaseCacheNode *>::iterator it)
{
	CaseCacheNode *node = it->second;

	m_map.erase(it);

	m_lru_list.erase(node->m_list_it);

	node->m_files.clear();

	m_spare_node_list.push_front(node);

}

bool CaseCache::purge(LPCWSTR path)
{
	bool bRet = true;

	std::wstring ucpath;

	if (!touppercase(path, ucpath))
		return false;

	lock();

	try {
	
		auto it = m_map.find(ucpath);

		if (it == m_map.end()) {
			DbgPrint(L"CaseCache.cpp thread %u exception at line %d\n",  GetCurrentThreadId(), __LINE__);
			throw(-1);
		}

		remove_node(it);

	} catch (...) {
		bRet = false;
	}

	unlock();

	return bRet;
}

// use our own callback so rest of the code doens't need to know about Dokany internals
static int WINAPI casecache_fill_find_data(PWIN32_FIND_DATAW fdata, void * dokan_cb, void * dokan_ctx)
{
	std::list<std::wstring> *plist = (std::list<std::wstring> *)dokan_ctx;

	plist->push_back(fdata->cFileName);

	return 0;
}

bool CaseCache::loaddir(LPCWSTR filepath)
{

	if (!m_con->IsCaseInsensitive())
		return true;

	std::wstring dir;
	
	if (!get_dir_and_file_from_path(filepath, &dir, NULL)) {
		return false;
	}

	std::wstring case_dir;

	int status = lookup(dir.c_str(), case_dir);

	if (status != CASE_CACHE_MISS  && status != CASE_CACHE_FOUND)
		return false;

	if (status == CASE_CACHE_MISS) {
		if (!loaddir(dir.c_str()))
			return false;

		status = lookup(dir.c_str(), case_dir);
	}  

	if (status != CASE_CACHE_FOUND)
		return false;

	std::wstring enc_dir;
	
	if (!encrypt_path(m_con, case_dir.c_str(), enc_dir)) {
		return false;
	}

	std::list<std::wstring> list;

	if (find_files(m_con, case_dir.c_str(), enc_dir.c_str(), casecache_fill_find_data, NULL, &list) != 0) {
		return false;
	}

	return store(case_dir.c_str(), list);
}

// when a directory is renamed, do a search and replace in the cache

bool CaseCache::rename(LPCWSTR oldpath, LPCWSTR newpath)
{
	bool bRet = true;

	std::wstring ucold;

	if (!touppercase(oldpath, ucold))
		return false;

	std::wstring ucnew;

	if (!touppercase(newpath, ucnew))
		return false;

	size_t oldlen = ucold.length();

	size_t newlen = ucnew.length();

	std::wstring newkey;

	std::list<std::wstring> toerase;

	std::list<std::pair<std::wstring, CaseCacheNode *>> toinsert;

	lock();

	try {

		for (auto it : m_map) {
			size_t keylen = it.first.length();

			if (keylen < oldlen)
				continue;

			if (wcsncmp(ucold.c_str(), it.first.c_str(), oldlen)) 
				continue;

			newkey = ucnew + it.first.substr(oldlen);

			it.second->m_path = newpath + it.second->m_path.substr(oldlen);

			toerase.push_back(it.first);

			toinsert.push_back(std::make_pair(newkey, it.second));
		} 

		for (auto it : toerase) {
			m_map.erase(it);
		}

		for (auto it : toinsert) {
			m_map.insert(it);
		}
	
	} catch (...) {
		bRet = false;
	}

	unlock();

	return bRet;
}
