#pragma once

#include <string>

template<typename T>
class LockZeroBuffer
{
	BOOL m_IsLocked;
public:
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
			
			SIZE_T min_ws, max_ws;

			if (GetProcessWorkingSetSize(GetCurrentProcess(), &min_ws, &max_ws)) {
				min_ws = max(1024 * 1024, min_ws);
				max_ws = max(max_ws, min_ws);
				if (SetProcessWorkingSetSize(GetCurrentProcess(), min_ws, max_ws)) {
					m_IsLocked = VirtualLock(m_buf, sizeof(T)*m_len);
				}
			}
		}
		if (!m_IsLocked && throw_if_not_locked) {
			delete[] m_buf;
			std::bad_alloc exception;
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

