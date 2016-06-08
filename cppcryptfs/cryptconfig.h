#pragma once

#include <windows.h>
#include <vector>


class CryptConfig
{
public:
	int m_N;
	int m_R;
	int m_P;
	int m_KeyLen;

	bool m_PlaintextNames;
private:
	bool m_DirIV;
public:
	bool DirIV() { return m_DirIV; };
	bool m_EMENames;
	bool m_GCMIV128;
	bool m_LongNames;

	int m_Version;
	std::wstring m_VolumeName;

	std::vector<unsigned char> m_encrypted_key_salt;
	std::vector<unsigned char> m_encrypted_key;
	unsigned char * m_key;

	std::wstring m_basedir;

	char m_driveletter;

	const unsigned char *GetKey() { return m_key; };
	WCHAR GetDriveLetter() { return m_driveletter; };
	const WCHAR *GetBaseDir() { return &m_basedir[0]; }

	CryptConfig();
	bool read();
	bool decrypt_key(LPCTSTR password);

	bool create(const WCHAR *path, const WCHAR *password, bool eme, bool plaintext, bool longfilenames, const WCHAR *volume_name, std::wstring& error_mes);

	bool check_config(std::wstring& mes);

	virtual ~CryptConfig();
};



