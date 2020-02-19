/*
cppcryptfs : user-mode cryptographic virtual overlay filesystem.

Copyright (C) 2016-2020 Bailey Brown (github.com/bailey27/cppcryptfs)

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
#include "KeybufManager.h"
#include <Wincrypt.h>
#include "util/util.h"
#include "util/KeyCache.h"

KeybufManager::KeybufManager()
{
	m_bActive = false;
	m_bFinalized = false;
	m_refcount = 0;
	m_total_len = 0;
	m_key_cache_id = 0;
}

KeybufManager::~KeybufManager()
{
	if (m_key_cache_id) {
		KeyCache::GetInstance()->Unregister(m_key_cache_id);
	}
}

void KeybufManager::RegisterBuf(BYTE* p, DWORD len)
{
	if (!m_bActive)
		return;

	if (m_bFinalized)
		throw std::exception("KeyBufManager::RegisterBuf called while finalized");

	KeyBuf buf;

	buf.ptr = p;
	buf.len = len;
	
	m_total_len += len;

	m_bufs.push_back(buf);
}

bool KeybufManager::Finalize(bool use_key_cache)
{
	if (!m_bActive)
		return true;

	if (m_bFinalized)
		throw std::exception("KeybufManger::Finalize called when already finalized");

	if (!m_total_len || m_bufs.size() < 1) 
		throw std::exception("KeybufManger::Finalize called with no buffers");

	LockZeroBuffer<BYTE> DecryptBuf(static_cast<DWORD>(m_total_len), true, nullptr);

	size_t offset = 0;
	for (size_t i = 0; i < m_bufs.size(); i++) {
		memcpy(DecryptBuf.m_buf + offset, m_bufs[i].ptr, m_bufs[i].len);
		SecureZeroMemory(m_bufs[i].ptr, m_bufs[i].len);
		offset += m_bufs[i].len;
	}

	get_sys_random_bytes(m_optional_entropy, sizeof(m_optional_entropy));

	DATA_BLOB key_blob;
	DATA_BLOB enc_key_blob;
	DATA_BLOB optional_entropy;

	optional_entropy.cbData = static_cast<DWORD>(sizeof(m_optional_entropy));
	optional_entropy.pbData = m_optional_entropy;

	key_blob.cbData = static_cast<DWORD>(DecryptBuf.m_len);
	key_blob.pbData = DecryptBuf.m_buf;

	bool bResult = CryptProtectData(&key_blob, NULL, &optional_entropy, NULL, NULL, 0, &enc_key_blob);

	if (!bResult) {
		throw std::exception("KeybufManager unable to encrypt password buf");
	}

	m_encryptedBuf.resize(enc_key_blob.cbData);
	memcpy(&m_encryptedBuf[0], enc_key_blob.pbData, enc_key_blob.cbData);

	LocalFree(enc_key_blob.pbData);

	if (use_key_cache) {
		m_key_cache_id = KeyCache::GetInstance()->Register(m_total_len);
	}

	return bResult;
}


bool KeybufManager::EnterInternal()
{

	lock_guard<mutex> lock(m_mutex);

	assert(m_refcount >= 0);

	m_refcount++;

	if (m_refcount > 1) {
		return true;
	}

	if (m_key_cache_id) {
		bool result = KeyCache::GetInstance()->Retrieve(m_key_cache_id, m_bufs);
		if (result) {
			return true;
		}
	}

	DATA_BLOB key_blob;
	DATA_BLOB enc_key_blob;

	DATA_BLOB optional_entropy;
	optional_entropy.cbData = static_cast<DWORD>(sizeof(m_optional_entropy));
	optional_entropy.pbData = m_optional_entropy;

	enc_key_blob.cbData = static_cast<DWORD>(m_encryptedBuf.size());
	enc_key_blob.pbData = &m_encryptedBuf[0];

	BOOL bResult = CryptUnprotectData(&enc_key_blob, NULL, &optional_entropy, NULL, NULL, 0, &key_blob);

	if (!bResult)
		throw std::exception("KeybufManager unable to decrypt keys");

	if (key_blob.cbData != m_total_len) {
		SecureZeroMemory(key_blob.pbData, key_blob.cbData);
		LocalFree(key_blob.pbData);
		throw std::exception("KeybufManager decrypted wrong number of bytes");
	}

	KeyCache::CopyBuffers(m_bufs, key_blob.pbData, key_blob.cbData);

	if (m_key_cache_id) {
		KeyCache::GetInstance()->Store(m_key_cache_id, key_blob.pbData, key_blob.cbData);
	}

	SecureZeroMemory(key_blob.pbData, key_blob.cbData);
	LocalFree(key_blob.pbData);

	return bResult;
}

void KeybufManager::LeaveInternal()
{
	lock_guard<mutex> lock(m_mutex);

	assert(m_refcount > 0);

	m_refcount--;

	if (m_refcount > 0)
		return;

	for (size_t i = 0; i < m_bufs.size(); i++) {
		SecureZeroMemory(m_bufs[i].ptr, m_bufs[i].len);
	}
}