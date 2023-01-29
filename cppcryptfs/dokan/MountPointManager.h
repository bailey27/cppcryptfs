#pragma once
/*
cppcryptfs : user-mode cryptographic virtual overlay filesystem.

Copyright (C) 2016-2023 Bailey Brown (github.com/bailey27/cppcryptfs)

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

#include <functional>

class CryptThreadData;

class MountPointManager {

private:
	unordered_map<wstring, CryptThreadData*> m_tdatas;
	MountPointManager() {}
public:    
	// disallow copying
	MountPointManager(MountPointManager const&) = delete;
	void operator=(MountPointManager const&) = delete;

	virtual ~MountPointManager();

	static MountPointManager& getInstance() {
		static MountPointManager instance;

		return instance;
	}
	
	
	
private:
	bool destroy(const wchar_t *mountpoint);
	BOOL wait_multiple_and_destroy(int count, HANDLE handles[], wstring mountpoints[]);
	bool unmount_all(bool wait);
	BOOL wait_and_destroy(const WCHAR* mountpoint);
	BOOL wait_all_and_destroy();
	// MountPointManager becomes owner of tdata
	bool add(const wchar_t *mountpoint, CryptThreadData* tdata);

	CryptThreadData *get(const wchar_t *mountpoint);

	void apply(function<bool(const wchar_t *mountpoint, CryptThreadData *tdata)> f );
public:
	bool empty() const { return m_tdatas.empty(); }
	bool get_path (const WCHAR *mountpoint, wstring& path) const;
	// returns actual mount point (in case used to mount it 
	// which is how the key is stored
	bool find (const WCHAR *mountpoint, wstring& mpstr) const;
	void get_mount_points(vector<wstring>& mps, function<bool(const wchar_t *)> filter = NULL) const;
    int get_open_handle_count(const wchar_t *mountpoint = nullptr);	

	// these functions in cryptdokan use the private methods of MountPointManager()

	friend int mount_crypt_fs(const WCHAR* mountpoint, const WCHAR *path,
		const WCHAR *config_path, const WCHAR *password,
		wstring &mes, bool reverse, bool readonly, const CryptMountOptions& opts);
	friend BOOL unmount_crypt_fs(const WCHAR* mountpoint, bool wait, wstring& mes);
	friend bool unmount_all(bool wait);
	friend BOOL wait_for_all_unmounted();
	friend BOOL list_files(const WCHAR *path, list<FindDataPair> &findDatas,
		wstring &err_mes);
	friend BOOL write_volume_name_if_changed(WCHAR dl, wstring& mes);
	friend bool get_fs_info(const wchar_t *mountpoint, FsInfo& info);
	friend std::wstring transform_path(const wchar_t* path, wstring& mes);
};

