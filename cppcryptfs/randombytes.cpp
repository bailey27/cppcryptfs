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
#include "util.h"
#include "randombytes.h"

RandomBytes::RandomBytes()
{

	m_pRandBuf = new LockZeroBuffer<BYTE>(RANDOM_POOL_SIZE);

	if (!m_pRandBuf->IsLocked()) {
		delete m_pRandBuf;
		m_pRandBuf = NULL;
		::MessageBox(NULL, L"cannot lock random pool", L"cppcryptfs", MB_OK | MB_ICONERROR);
		std::bad_alloc exception;
		throw exception;
	}

	m_randbuf = m_pRandBuf->m_buf;

	m_bufpos = RANDOM_POOL_SIZE;

	InitializeCriticalSection(&m_crit);
}

RandomBytes::~RandomBytes()
{
	// do not free m_randbuf.  It points to m_pRandBuf->m_buf
	if (m_pRandBuf)
		delete m_pRandBuf;
}

void RandomBytes::lock()
{
	EnterCriticalSection(&m_crit);
}

void RandomBytes::unlock()
{
	LeaveCriticalSection(&m_crit);
}

bool RandomBytes::GetRandomBytes(unsigned char *buf, DWORD len)
{
	if (len > RANDOM_POOL_SIZE) {
		return get_sys_random_bytes(buf, len);
	}

	bool bret = true;

	lock();

	if (m_bufpos + len < RANDOM_POOL_SIZE) {
		memcpy(buf, m_randbuf + m_bufpos, len);
		m_bufpos += len;
	} else {
		DWORD bytes_copied = 0;
		if (m_bufpos < RANDOM_POOL_SIZE) {
			memcpy(buf, m_randbuf + m_bufpos, RANDOM_POOL_SIZE - m_bufpos);
			bytes_copied += RANDOM_POOL_SIZE - m_bufpos;
			m_bufpos += bytes_copied;
		}
		if (get_sys_random_bytes(m_randbuf, RANDOM_POOL_SIZE)) {
			m_bufpos = 0;
			memcpy(buf + bytes_copied, m_randbuf + m_bufpos, len - bytes_copied);
			m_bufpos += len - bytes_copied;
		} else {
			bret = false;
		}
	}

	unlock();

	return bret;
}
