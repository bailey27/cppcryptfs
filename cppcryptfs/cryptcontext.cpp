#include "stdafx.h"
#include "cryptcontext.h"

void CryptContext::InitEme(BYTE *key)
{
	m_eme.key = key;
	m_eme.lc = NULL;
	m_lc.init(&m_eme);
	m_eme.lc = &m_lc;
}

CryptContext::CryptContext()
{
	m_mounted = FALSE;
	m_config = new CryptConfig;
}

CryptContext::~CryptContext()
{
	if (m_config)
		delete m_config;
}