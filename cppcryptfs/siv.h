#pragma once

#include "LockZeroBuffer.h"
#include "openssl/aes.h"

#define SIV_KEY_ENCRYPT_LOW_INDEX  0
#define SIV_KEY_DECRYPT_LOW_INDEX  1
#define SIV_KEY_ENCRYPT_HIGH_INDEX 2
#define SIV_KEY_DECRYPT_HIGH_INDEX 3

class SivContext {

public:

	bool SetKey(const unsigned char *key, int keylen); // must be 32

	SivContext();
	virtual ~SivContext();

	const AES_KEY *GetEncryptKeyLow() const { return m_pKeys ? &m_pKeys->m_buf[SIV_KEY_ENCRYPT_LOW_INDEX] : NULL; };
	const AES_KEY *GetDecryptKeyLow() const { return m_pKeys ? &m_pKeys->m_buf[SIV_KEY_DECRYPT_LOW_INDEX] : NULL; };
	const AES_KEY *GetEncryptKeyHigh() const { return m_pKeys ? &m_pKeys->m_buf[SIV_KEY_ENCRYPT_HIGH_INDEX] : NULL; };
	const AES_KEY *GetDecryptKeyHigh() const { return m_pKeys ? &m_pKeys->m_buf[SIV_KEY_DECRYPT_HIGH_INDEX] : NULL; };
	
private:
	LockZeroBuffer<AES_KEY> *m_pKeys;
};