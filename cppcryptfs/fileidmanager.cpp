#include "stdafx.h"
#include "fileidmanager.h"
#include "fileutil.h"
#include "cryptfile.h"
#include "util.h"
#include "cryptcontext.h"

FileIdNode::FileIdNode()
{
	m_refcount = 0;
	m_is_empty = true;
	memset(&m_fileid, 0, FILE_ID_LEN);
	m_real_file_size = 0;
}

FileIdNode::~FileIdNode()
{
}

FileIdManager::FileIdManager()
{
	InitializeCriticalSection(&m_crit);
}

FileIdManager::~FileIdManager()
{
	for (auto it : m_map) {
		FileIdNode *node = it.second;
		delete node;
	}
}

void FileIdManager::normalize_key(std::wstring& key)
{

}

void FileIdManager::lock()
{
	EnterCriticalSection(&m_crit);
}

void FileIdManager::unlock()
{
	LeaveCriticalSection(&m_crit);
}

bool FileIdManager::openfile(LPCWSTR path, HANDLE hfile)
{
	std::wstring key = path;

	normalize_key(key);

	lock();

	auto it = m_map.find(key);

	if (it != m_map.end()) {
		FileIdNode *node = it->second;
		
		node->m_refcount++;

		unlock();

		return true;
	}

	FileIdNode *node = new FileIdNode;

	LARGE_INTEGER l;

	if (!GetFileSizeEx(hfile, &l)) {
		DbgPrint(L"FileIdManger: failed to get size of file\n");
		delete node;
		unlock();
		return false;
	}

	node->m_real_file_size = l.QuadPart;

	if (l.QuadPart == 0) {
		node->m_is_empty = true;
		node->m_refcount++;
		m_map.insert(std::make_pair(key, node));
		unlock();
		return true;
	} else if (l.QuadPart < FILE_HEADER_LEN) {
		DbgPrint(L"FileIdManger: missing file header\n");
		delete node;
		unlock();
		return false;
	}

	l.QuadPart = 0;

	if (!SetFilePointerEx(hfile, l, NULL, FILE_BEGIN)) {
		DbgPrint(L"FileIdManger: failed to seek\n");
		delete node;
		unlock();
		return false;
	}

	DWORD nread;
	FileHeader header;

	if (!ReadFile(hfile, &header, sizeof(header), &nread, NULL)) {
		DbgPrint(L"FileIdManger: failed to read header\n");
		delete node;
		unlock();
		return false;
	}

	if (nread != FILE_HEADER_LEN) {
		DbgPrint(L"FileIdManger: wrong number of bytes read when reading file header\n");
		delete node;
		unlock();
		return false;
	}

	header.version = MakeBigEndianNative(header.version);

	if (header.version != CRYPT_VERSION) {
		DbgPrint(L"FileIdManger: file version mismatch\n");
		delete node;
		unlock();
		return false;
	}

	static BYTE zerobytes[FILE_ID_LEN] = { 0 };

	if (!memcmp(header.fileid, zerobytes, sizeof(header.fileid))) {
		DbgPrint(L"FileIdManger: fileid is all zeroes\n");
		delete node;
		unlock();
		return false;
	}

	node->m_is_empty = false;
	node->m_refcount++;
	memcpy(node->m_fileid, header.fileid, FILE_ID_LEN);

	m_map.insert(std::make_pair(key, node));

	unlock();

	return true;
}

void FileIdManager::closefile(LPCWSTR path)
{

	std::wstring key = path;

	normalize_key(key);

	lock();

	auto it = m_map.find(key);

	if (it != m_map.end()) {
		FileIdNode *node = it->second;

		node->m_refcount--;

		if (node->m_refcount == 0) {
			m_map.erase(key);
			delete node;
		}

	}

	unlock();
}


bool FileIdManager::get(LPCWSTR path, unsigned char *fileid, bool& is_empty, LONGLONG& real_file_size)
{
	std::wstring key = path;

	normalize_key(key);

	lock();

	bool bRet;

	auto it = m_map.find(key);

	if (it != m_map.end()) {

		bRet = true;

		FileIdNode *node = it->second;
		
		is_empty = node->m_is_empty;

		if (!is_empty) {
			memcpy(fileid, node->m_fileid, FILE_ID_LEN);
		}

		real_file_size = node->m_real_file_size;

	} else {
		bRet = false;
	}

	unlock();

	return bRet;
}


bool FileIdManager::writeheader(CryptContext *con, LPCWSTR path, HANDLE h, unsigned char *fileid)
{
	std::wstring key = path;

	normalize_key(key);

	lock();

	bool bRet;

	auto it = m_map.find(key);

	if (it != m_map.end()) {

		FileIdNode *node = it->second;

		if (!node->m_is_empty) {
			DbgPrint(L"FileIdManger: writing fileid on non-empty file\n");
			unlock();
			return false;
		}

		LARGE_INTEGER l;
		l.QuadPart = 0;

		if (!SetFilePointerEx(h, l, NULL, FILE_BEGIN)) {
			DbgPrint(L"FileIdManger: SetFilePointerEx failed\n");
			unlock();
			return false;
		}

		FileHeader header;

		if (!get_random_bytes(con, node->m_fileid, FILE_ID_LEN)) {
			DbgPrint(L"FileIdManger: get_random_bytes failed\n");
			unlock();
			return false;
		}

		memcpy(header.fileid, node->m_fileid, FILE_ID_LEN);
		memcpy(fileid, node->m_fileid, FILE_ID_LEN);

		unsigned short version = CRYPT_VERSION;

		header.version = MakeBigEndian(version);

		DWORD nWritten = 0;

		if (!WriteFile(h, &header, sizeof(header), &nWritten, NULL)) {
			DbgPrint(L"FileIdManger: WriteFile failed\n");
			header.version = CRYPT_VERSION;
			unlock();
			return false;
		}

		header.version = CRYPT_VERSION;

		node->m_is_empty = false;

		bRet = nWritten == FILE_HEADER_LEN;

		if (!bRet) {
			DbgPrint(L"FileIdManger: WriteFile wrote incorrect number of bytes\n");
		}

	} else {
		DbgPrint(L"FileIdManger: node not found in write\n");
		bRet = false;
	}

	unlock();

	return bRet;

}

bool FileIdManager::truncated_to_zero(LPCWSTR path)
{
	std::wstring key = path;

	normalize_key(key);

	lock();

	bool bRet;

	auto it = m_map.find(key);

	if (it != m_map.end()) {

		FileIdNode *node = it->second;

		bRet = true;

		node->m_is_empty = true;

	} else {
		bRet = false;
	}

	unlock();

	return bRet;
}


bool FileIdManager::update_file_size(LPCWSTR path, LONGLONG offset, bool truncating)
{
	std::wstring key = path;

	normalize_key(key);

	lock();

	bool bRet;

	auto it = m_map.find(key);

	if (it != m_map.end()) {

		FileIdNode *node = it->second;

		bRet = true;

		LARGE_INTEGER l;
		l.QuadPart = offset;
		if (adjust_file_offset_up_truncate_zero(l)) {
			if (truncating) {
				node->m_real_file_size = l.QuadPart;
			} else {
				node->m_real_file_size = max(l.QuadPart, node->m_real_file_size);
			}
			if (node->m_real_file_size == 0)
				node->m_is_empty = true;
		} else {
			bRet = false;
		}

	} else {
		bRet = false;
	}

	unlock();

	return bRet;
}