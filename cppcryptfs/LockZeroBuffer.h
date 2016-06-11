#pragma once
template<typename T>
class LockZeroBuffer
{
	BOOL m_IsLocked;
public:
	BOOL IsLocked() { return m_IsLocked; };
	T *m_buf;
	unsigned int m_len;

	LockZeroBuffer(unsigned int len)
	{
		m_len = len;
		m_buf = new T[m_len];
		m_IsLocked = VirtualLock(m_buf, sizeof(T)*m_len);
		m_buf[0] = 0;
	}

	virtual ~LockZeroBuffer()
	{
		if (m_buf) {
			SecureZeroMemory(m_buf, sizeof(T)*m_len);
			if (m_IsLocked)
				VirtualUnlock(m_buf, sizeof(T)*m_len);
			delete[] m_buf;
		}
	}
};

