#pragma once

#include "cryptdefs.h"


#include <unordered_map>
#include <list>

class CryptContext;

class FileIdNode {

public:
	const std::wstring *m_key; // (encrypted) path to file
	unsigned char m_fileid[FILE_ID_LEN];
	LONGLONG m_real_file_size; 
	int m_refcount;
	bool m_is_empty;
	FileIdNode();
	virtual ~FileIdNode();
};



class FileIdManager {

private:


	std::unordered_map<std::wstring, FileIdNode*> m_map;

	CRITICAL_SECTION m_crit;

	long long m_lookups;
	long long m_hits;

	void normalize_key(std::wstring &key);

	void lock();
	void unlock();


public:


	// these are called when a file is opened or closed.  increment/decrement ref count
	bool openfile(LPCWSTR path, HANDLE h); // encrypted path
	void closefile(LPCWSTR path);

	// get returns the fileid and whether the file is empty
	bool get(LPCWSTR path, unsigned char *fileid, bool& is_empty, LONGLONG& real_file_size);

	// should be called the first time an empty file is written to
	bool write(CryptContext *con, LPCWSTR path, HANDLE h, unsigned char *fileid);

	// called if the file is truncated to zero, resets empty to true
	bool truncated_to_zero(LPCWSTR path);

	// called when the file size should be updated (write or set end of file)
	// offset is needs to be adjusted up to real file size
	bool update_file_size(LPCWSTR path, LONGLONG offset, bool truncating);

	FileIdManager();

	virtual ~FileIdManager();

};