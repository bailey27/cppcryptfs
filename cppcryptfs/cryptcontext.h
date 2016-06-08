#pragma once

#include "cryptconfig.h"
#include <windows.h>
#include <vector>
#include "eme.h"

class CryptContext {
private:

	CryptConfig *m_config;
public:

	EmeCryptContext m_eme;
	lCacheContainer m_lc; // for eme

	BOOL m_mounted;

	void InitEme(BYTE *key);

	CryptContext();

	CryptConfig *GetConfig() { return m_config; };

	virtual ~CryptContext();
};