/*
cppcryptfs : user-mode cryptographic virtual overlay filesystem.

Copyright (C) 2016-2019 Bailey Brown (github.com/bailey27/cppcryptfs)

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
#include "wintypes.h"
#include <string>

using namespace std;

template<typename T>
class LockZeroBuffer
{
private:
	BOOL m_IsLocked;
public:
	// disallow copying
	LockZeroBuffer(LockZeroBuffer const&) = delete;
	void operator=(LockZeroBuffer const&) = delete;

	BOOL IsLocked() { return m_IsLocked; };
	T *m_buf;
	unsigned int m_len;

	void Clear() 
	{
		if (m_buf)
			SecureZeroMemory(m_buf, sizeof(T)*m_len);
	}

	LockZeroBuffer(unsigned int len, bool throw_if_not_locked = false)
	{
		m_len = len;
		m_buf = new T[m_len];
		m_IsLocked = VirtualLock(m_buf, sizeof(T)*m_len);
		if (!m_IsLocked) {
			// The amount of memory that can be locked is a little bit less than the
			// minimum working set size, which defaults to 200KB.
			//
			// Attempt to increase the minimum working set size to 1MB
			
			const SIZE_T desired_min_ws = 1024 * 1024;

			SIZE_T min_ws, max_ws;

			if (GetProcessWorkingSetSize(GetCurrentProcess(), &min_ws, &max_ws)) {
				if (min_ws < desired_min_ws) {
					max_ws = max(max_ws, desired_min_ws);
					if (SetProcessWorkingSetSize(GetCurrentProcess(), desired_min_ws, max_ws)) {
						m_IsLocked = VirtualLock(m_buf, sizeof(T)*m_len);
					}
				}
			}
		}
		if (!m_IsLocked && throw_if_not_locked) {
			delete[] m_buf;
			bad_alloc exception;
			throw exception;
		}
		memset(m_buf, 0, sizeof(T)*m_len);
	}

	virtual ~LockZeroBuffer()
	{
		if (m_buf) {
			Clear();
			if (m_IsLocked)
				VirtualUnlock(m_buf, sizeof(T)*m_len);
			delete[] m_buf;
		}
	}
};

