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
		memset(m_buf, 0, sizeof(T)*m_len);
		if (!m_IsLocked && throw_if_not_locked) {
			std::bad_alloc exception;
			throw exception;
		}
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

