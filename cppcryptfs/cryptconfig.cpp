/*
cppcryptfs : user-mode cryptographic virtual overlay filesystem.

Copyright (C) 2016 - Bailey Brown (github.com/bailey27/cppcryptfs)

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

#include <iostream>
#include <fstream>

#include "cryptconfig.h"


#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/filewritestream.h"
#include "rapidjson/prettywriter.h"
#include <cstdio>

#include "util.h"
#include "cryptdefs.h"
#include "scrypt.h"
#include "crypt.h"
#include "fileutil.h"
#include "PasswordBuffer.h"

CryptConfig::CryptConfig()
{
	m_N = 0;
	m_R = 0;
	m_P = 0;
	m_KeyLen = 0;

	m_PlaintextNames = false;
	m_DirIV = false;
	m_EMENames = false;
	m_GCMIV128 = false;
	m_LongNames = false;

	m_key = NULL;

	m_Version = 0;

}


CryptConfig::~CryptConfig()
{
	if (m_key && m_KeyLen > 0) {
		DbgPrint(L"deleting %c:\n", m_driveletter);
		SecureZeroMemory(m_key, m_KeyLen);
		VirtualUnlock(m_key, m_KeyLen);
	}
	if (m_key) {
		delete[] m_key;
	}
}


bool
CryptConfig::read(const WCHAR *configfile)
{


	std::wstring config_path;

	if (configfile) {
		config_path = configfile;
	} else {

		if (m_basedir.size() < 1)
			return false;

		config_path = m_basedir;

		if (config_path[config_path.size() - 1] != '\\')
			config_path.push_back('\\');

		config_path += CONFIG_NAME;

	}

	const WCHAR *path = &config_path[0];

	FILE *fl = NULL;

	if (_wfopen_s(&fl, path, L"rb"))
		return false;

	if (fseek(fl, 0, SEEK_END))
		return false;

	long filesize = ftell(fl);

	if (fseek(fl, 0, SEEK_SET))
		return false;

	char *buf = new char[filesize + 1];

	if (!buf)
		return false;

	size_t len = fread(buf, 1, filesize, fl);

	fclose(fl);

	if (len < 0)
		return false;

	buf[len] = '\0';

	rapidjson::Document d;

	d.Parse(buf);

	delete[] buf;

	bool bret = true;

	try {

		if (!d.HasMember("EncryptedKey") || !d["EncryptedKey"].IsString())
			return false;

		rapidjson::Value& v = d["EncryptedKey"];

		if (!base64_decode(v.GetString(), m_encrypted_key, false))
			return false;

		if (!d.HasMember("ScryptObject") || !d["ScryptObject"].IsObject())
			return false;

		rapidjson::Value& scryptobject = d["ScryptObject"];


		if (!base64_decode(scryptobject["Salt"].GetString(), m_encrypted_key_salt, false))
			return false;

		const char *sstuff[] = { "N", "R", "P", "KeyLen" };

		int i;

		for (i = 0; i < sizeof(sstuff) / sizeof(sstuff[0]); i++) {
			if (scryptobject[sstuff[i]].IsNull() || !scryptobject[sstuff[i]].IsInt()) {
				return false;
			}
		}

		m_N = scryptobject["N"].GetInt();
		m_R = scryptobject["R"].GetInt();
		m_P = scryptobject["P"].GetInt();
		m_KeyLen = scryptobject["KeyLen"].GetInt();

		if (d["Version"].IsNull() || !d["Version"].IsInt()) {
			return false;
		}
		rapidjson::Value& version = d["Version"];

		m_Version = version.GetInt();

		if (d.HasMember("VolumeName") && !d["VolumeName"].IsNull() && d["VolumeName"].IsString()) {
			rapidjson::Value& volume_name = d["VolumeName"];
			std::string utf8name;
			utf8name = volume_name.GetString();
			std::wstring storage;
			const WCHAR *vname = utf8_to_unicode(&utf8name[0], storage);
			if (vname)
				m_VolumeName = vname;
		}

		if (d.HasMember("FeatureFlags") && !d["FeatureFlags"].IsNull() && d["FeatureFlags"].IsArray()) {
			rapidjson::Value& flags = d["FeatureFlags"];

			/*

			bool m_PlaintextNames;
			bool m_DirIV;
			bool m_EMENames;
			bool m_GCMIV128;
			bool m_LongNames;
			*/

			for (rapidjson::Value::ConstValueIterator itr = flags.Begin(); itr != flags.End(); ++itr) {
				if (itr->IsString()) {
					if (!strcmp(itr->GetString(), "PlaintextNames")) {
						m_PlaintextNames = true;
					}
					else if (!strcmp(itr->GetString(), "DirIV")) {
						m_DirIV = true;
					}
					else if (!strcmp(itr->GetString(), "EMENames")) {
						m_EMENames = true;
					}
					else if (!strcmp(itr->GetString(), "GCMIV128")) {
						m_GCMIV128 = true;
					}
					else if (!strcmp(itr->GetString(), "LongNames")) {
						m_LongNames = true;
					}
				}
			}
		}
	} catch (...) {
		bret = false;
	}

	return bret;
}

bool CryptConfig::write_volume_name()
{
	bool bret = true;

	try {
		std::wstring vol = m_VolumeName;

		std::string volume_name_utf8_enc;

		if (vol.size() > MAX_VOLUME_NAME_LENGTH)
			vol.erase(MAX_VOLUME_NAME_LENGTH, std::wstring::npos);
		if (!encrypt_string_gcm(vol, m_key, volume_name_utf8_enc)) {
			return false;
		}

		if (m_basedir.size() < 1)
			return false;

		std::wstring config_path;

		config_path = m_basedir;

		if (config_path[config_path.size() - 1] != '\\')
			config_path.push_back('\\');

		config_path += CONFIG_NAME;

		const WCHAR *path = &config_path[0];

		FILE *fl = NULL;

		if (_wfopen_s(&fl, path, L"rb"))
			return false;

		if (fseek(fl, 0, SEEK_END))
			return false;

		long filesize = ftell(fl);

		if (fseek(fl, 0, SEEK_SET))
			return false;

		char *buf = new char[filesize + 1];

		if (!buf)
			return false;

		size_t len = fread(buf, 1, filesize, fl);

		fclose(fl);

		if (len < 0)
			return false;

		buf[len] = '\0';

		rapidjson::Document d;

		d.Parse(buf);

		delete[] buf;

		FILE *fp = NULL;

		rapidjson::Value vname(volume_name_utf8_enc.c_str(), d.GetAllocator());

		if (d.HasMember("VolumeName")) {
			d["VolumeName"] = vname;
		}
		else {
			d.AddMember("VolumeName", vname, d.GetAllocator());
		}
		std::wstring tmp_path = config_path;
		tmp_path += L".tmp";
		if (_wfopen_s(&fp, &tmp_path[0], L"wb"))
			return false;
		char writeBuffer[65536];
		rapidjson::FileWriteStream os(fp, writeBuffer, sizeof(writeBuffer));
		rapidjson::PrettyWriter<rapidjson::FileWriteStream> writer(os);
		d.Accept(writer);
		fclose(fp);

		CryptConfig test_cfg;

		try {
			if (!test_cfg.read(&tmp_path[0])) {
				throw(-1);
			}
		} catch (...) {
			DeleteFile(&tmp_path[0]);
			return false;
		}

		DWORD dwAttr = GetFileAttributes(&config_path[0]);

		if (dwAttr == INVALID_FILE_ATTRIBUTES) {
			DeleteFile(&tmp_path[0]);
			return false;
		}

		bool bWasReadOnly = false;

		if (dwAttr & FILE_ATTRIBUTE_READONLY) {

			bool bWasReadOnly = true;

			dwAttr &= ~FILE_ATTRIBUTE_READONLY;

			if (!SetFileAttributes(&config_path[0], dwAttr)) {
				DeleteFile(&tmp_path[0]);
				return false;
			}
		}

		if (!MoveFileEx(&tmp_path[0], &config_path[0], MOVEFILE_REPLACE_EXISTING)) {
			DeleteFile(&tmp_path[0]);
			return false;
		}

		if (bWasReadOnly) {
			dwAttr = GetFileAttributes(&config_path[0]);

			if (dwAttr == INVALID_FILE_ATTRIBUTES) {
				return false;
			}

			if (!(dwAttr & FILE_ATTRIBUTE_READONLY)) {
				dwAttr |= FILE_ATTRIBUTE_READONLY;

				if (!SetFileAttributes(&config_path[0], dwAttr)) {
					return false;
				}
			}
		}
	} catch (...) {
		bret = false;
	}

	return bret;
}

WCHAR CryptConfig::get_base_drive_letter()
{
	const WCHAR *p = &this->m_basedir[0];

	while (*p && *p != ':')
		p++;

	if (p > &this->m_basedir[0] && *p == ':') {
		return *(p - 1);
	}
	else {
		return 0;
	}
}

bool CryptConfig::check_config(std::wstring& mes)
{
	mes = L"";

	if (m_Version != 2)
		mes += L"Only version 2 is supported\n";

	if (0 && m_PlaintextNames) 
		mes += L"PlaintextNames not supported\n";
	
	if (0 && (!m_DirIV && !m_PlaintextNames)) 
		mes += L"DirIV must be specified unless PlaintextNames is used\n";

	if (0 && m_EMENames) 
		mes += L"EMENames not supported\n";
	
	if (!m_GCMIV128) 
		mes += L"GCMIV128 must be specified\n";

	if (0 && m_LongNames) 
		mes += L"LongNames not supported\n";
		
	return mes.size() == 0;
}

bool CryptConfig::decrypt_key(LPCTSTR password)
{
	unsigned char *pwkey = NULL;

	bool bret = true;

	void *context = NULL;

	try {
		if (m_encrypted_key.size() == 0 || m_encrypted_key_salt.size() == 0 || m_KeyLen == 0)
			return false;

		PasswordBufferUtf8 pass_buf;

		const char *pass = unicode_to_utf8(password, pass_buf.m_buf, sizeof(pass_buf.m_buf)-1);

		if (!pass) {
			throw (-1);
		}

		pwkey = new unsigned char[m_KeyLen];

		if (!VirtualLock(pwkey, m_KeyLen)) {
			delete[] pwkey;
			pwkey = NULL;
			throw(-1);
		}

		int result = EVP_PBE_scrypt(pass, strlen(pass), &(m_encrypted_key_salt)[0], m_encrypted_key_salt.size(), m_N, m_R, m_P, 96 * 1024 * 1024, pwkey,
			m_KeyLen);

		if (result != 1)
			throw (-1);

		unsigned char adata[8];

		const int adata_len = sizeof(adata);

		ZeroMemory(adata, adata_len);

		int ivlen = MASTER_IV_LEN;

		const int taglen = BLOCK_TAG_LEN;

		unsigned char *ciphertext = &(m_encrypted_key)[0] + ivlen;
		int ciphertext_len = (int)m_encrypted_key.size() - ivlen - taglen;
		unsigned char *tag = &(m_encrypted_key)[0] + m_encrypted_key.size() - taglen;

		unsigned char *iv = &(m_encrypted_key)[0];

		if (ciphertext_len != MASTER_KEY_LEN)
			throw (-1);

		context = get_crypt_context(ivlen, AES_MODE_GCM);

		if (!context)
			throw(-1);

		m_key = new unsigned char[MASTER_KEY_LEN];

		if (!VirtualLock(m_key, MASTER_KEY_LEN))
			throw(-1);

		int ptlen = decrypt(ciphertext, ciphertext_len, adata, adata_len, tag, pwkey, iv, m_key, context);

		if (ptlen != MASTER_KEY_LEN)
			throw (-1);

		if (m_VolumeName.size() > 0) {
			std::string vol;
			if (unicode_to_utf8(&m_VolumeName[0], vol)) {
				if (!decrypt_string_gcm(vol, m_key, m_VolumeName))
					m_VolumeName = L"";
				if (m_VolumeName.size() > MAX_VOLUME_NAME_LENGTH)
					m_VolumeName.erase(MAX_VOLUME_NAME_LENGTH, std::wstring::npos);
			} else {
				m_VolumeName = L"";
			}
		}

	} catch (...) {
		bret = false;
	}

	if (context)
		free_crypt_context(context);

	if (pwkey) {
		SecureZeroMemory(pwkey, m_KeyLen);
		VirtualUnlock(pwkey, m_KeyLen);
		delete[] pwkey;
	}

	return bret;
}

bool CryptConfig::create(const WCHAR *path, const WCHAR *password, bool eme, bool plaintext, bool longfilenames, const WCHAR *volume_name, std::wstring& error_mes)
{

	char utf8pass[256];

	m_basedir = path;

	bool bret = true;

	FILE *fl = NULL;

	unsigned char *pwkey = NULL;

	unsigned char *masterkey = NULL;

	void *context = NULL;

	unsigned char *encrypted_key = NULL;

	if (eme)
		m_EMENames = TRUE;
	else if (plaintext)
		m_PlaintextNames = TRUE;

	if (!m_PlaintextNames)
		m_LongNames = longfilenames;

	try {
		if (!can_delete_directory(&m_basedir[0], TRUE)) {
			error_mes = L"root dir is not empty\n";
			throw(-1);
		}

		

		std::wstring config_path;

		config_path = m_basedir;

		if (config_path[config_path.size() - 1] != '\\')
			config_path.push_back('\\');

		config_path += CONFIG_NAME;

		unsigned char salt[32];

		if (!get_sys_random_bytes(salt, sizeof(salt)))
			throw(-1);

		m_encrypted_key_salt.resize(sizeof(salt));

		for (size_t i = 0; i < sizeof(salt); i++) {
			m_encrypted_key_salt[i] = salt[i];
		}

		m_N = 65536;
		m_R = 8;
		m_P = 1;
		m_KeyLen = 32;
		m_Version = 2;
		m_DirIV = !m_PlaintextNames;
		
		if (!unicode_to_utf8(password, utf8pass, sizeof(utf8pass) - 1)) 
			throw(-1);
		

		pwkey  = new unsigned char[m_KeyLen];

		int result = EVP_PBE_scrypt(utf8pass, strlen(utf8pass), &(m_encrypted_key_salt)[0], m_encrypted_key_salt.size(), m_N, m_R, m_P, 96 * 1024 * 1024, pwkey,
			m_KeyLen);

		if (result != 1)
			throw(-1);

		unsigned char iv[MASTER_IV_LEN];

		if (!get_sys_random_bytes(iv, sizeof(iv)))
			throw(-1);

		unsigned char adata[8];

		const int adata_len = sizeof(adata);

		ZeroMemory(adata, adata_len);

		masterkey = new unsigned char[m_KeyLen];

		if (!get_sys_random_bytes(masterkey, m_KeyLen))
			throw(-1);

		std::string volume_name_utf8;

		if (volume_name && wcslen(volume_name)) {
			std::wstring vol = volume_name;
			if (vol.size() > MAX_VOLUME_NAME_LENGTH)
				vol.erase(MAX_VOLUME_NAME_LENGTH, std::wstring::npos);
			if (!encrypt_string_gcm(vol, masterkey, volume_name_utf8)) {
				error_mes = L"cannot encrypt volume name\n";
				throw(-1);
			}
		}

		context = get_crypt_context(MASTER_IV_LEN, AES_MODE_GCM);

		if (!context)
			throw(-1);

		encrypted_key = new unsigned char[m_KeyLen + MASTER_IV_LEN + BLOCK_TAG_LEN];

		memcpy(encrypted_key, iv, sizeof(iv));

		int ctlen = encrypt(masterkey, m_KeyLen, adata, sizeof(adata), pwkey, iv, (encrypted_key + sizeof(iv)), encrypted_key + sizeof(iv) + m_KeyLen, context);

		if (ctlen < 1)
			throw(-1);

		std::string storage;

		const char *base64_key = base64_encode(encrypted_key, m_KeyLen + MASTER_IV_LEN + BLOCK_TAG_LEN, storage, false);

		if (!base64_key)
			throw(-1);

		if (_wfopen_s(&fl, &config_path[0], L"wb")) {
			error_mes = L"cannot create config file\n";
			throw(-1);
		}

		if (!fl) {
			error_mes = L"unable to open config file for writing\n";
			throw(-1);
		}

		fprintf(fl, "{\n");

		fprintf(fl, "\t\"EncryptedKey\": \"%s\",\n", base64_key);

		const char *base64_salt = base64_encode(salt, sizeof(salt), storage, false);

		fprintf(fl, "\t\"ScryptObject\": {\n");
		fprintf(fl, "\t\t\"Salt\": \"%s\",\n", base64_salt);
		fprintf(fl, "\t\t\"N\": %d,\n", m_N);
		fprintf(fl, "\t\t\"R\": %d,\n", m_R);
		fprintf(fl, "\t\t\"P\": %d,\n", m_P);
		fprintf(fl, "\t\t\"KeyLen\": %d\n", m_KeyLen);
		fprintf(fl, "\t},\n");
		fprintf(fl, "\t\"Version\": %d,\n", m_Version);
		fprintf(fl, "\t\"VolumeName\": \"%s\",\n", &volume_name_utf8[0]);
		fprintf(fl, "\t\"FeatureFlags\": [\n");
		if (m_EMENames)
			fprintf(fl, "\t\t\"EMENames\",\n");
		if (m_LongNames)
			fprintf(fl, "\t\t\"LongNames\",\n");
		if (m_PlaintextNames)
			fprintf(fl, "\t\t\"PlaintextNames\",\n");
		else if (m_DirIV)
			fprintf(fl, "\t\t\"DirIV\",\n");
		fprintf(fl, "\t\t\"GCMIV128\"\n");
		fprintf(fl, "\t]\n");
		fprintf(fl, "}\n");

		fclose(fl);
		fl = NULL;

		DWORD attr = GetFileAttributesW(&config_path[0]);
		if (attr != INVALID_FILE_ATTRIBUTES) {
			attr |= FILE_ATTRIBUTE_READONLY;
			SetFileAttributes(&config_path[0], attr);
		}

		if (m_DirIV) {
			if (!create_dir_iv(NULL, &m_basedir[0])) {
				error_mes = L"cannot create diriv file in root dir\n";
				throw(-1);
			}
		}

	} catch (...) {

		bret = false;
	}


	SecureZeroMemory(utf8pass, sizeof(utf8pass));
	

	if (pwkey) {
		SecureZeroMemory(pwkey, m_KeyLen);
		delete[] pwkey;
	}
	if (masterkey) {
		SecureZeroMemory(masterkey, m_KeyLen);
		delete[] masterkey;
	}

	if (encrypted_key) {
		delete[] encrypted_key;
	}

	if (context)
		free_crypt_context(context);

	if (fl)
		fclose(fl);

	return bret;
}


