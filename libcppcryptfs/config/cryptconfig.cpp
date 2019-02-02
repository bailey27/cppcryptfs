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


#include "stdafx.h"

#include <iostream>
#include <fstream>

#include <openssl/evp.h>

#include "cryptconfig.h"
#include <assert.h>
#include <Shlwapi.h>

// min() and max() macros cause compiler warnings with rapidjson

#pragma push_macro("min")
#pragma push_macro("max")

#undef min
#undef max

#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/filewritestream.h"
#include "rapidjson/prettywriter.h"

#pragma pop_macro("min")
#pragma pop_macro("max")

#include <cstdio>

#include "util/util.h"
#include "crypt/cryptdefs.h"
#include "crypt/crypt.h"
#include "util/fileutil.h"
#include "util/LockZeroBuffer.h"
#include "filename/cryptfilename.h"

#define SCRYPT_MB 72 // 65 seems to be enough, but allow more just in case

CryptConfig::CryptConfig()
{
	m_N = 0;
	m_R = 0;
	m_P = 0;
	

	m_PlaintextNames = false;
	m_DirIV = false;
	m_EMENames = false;
	m_GCMIV128 = false;
	m_LongNames = false;
	m_AESSIV = false;
	m_Raw64 = false;
	m_HKDF = false;
	m_reverse = false;
	
	m_pKeyBuf = NULL;

	m_Version = 0;

	m_serial = DEFAULT_VOLUME_SERIAL_NUMBER;

	m_pGcmContentKey = NULL;

}


CryptConfig::~CryptConfig()
{
	delete m_pKeyBuf;	
	delete m_pGcmContentKey;	
}


bool
CryptConfig::read(wstring& mes, const WCHAR *config_file_path, bool reverse)
{

	auto File = cppcryptfs::unique_ptr(static_cast<FILE*>(nullptr), fclose);
	FILE *fl = NULL;

	if (config_file_path) {
		
		if (_wfopen_s(&fl, config_file_path, L"rb")) {
			mes = L"failed to open config file";
			return false;
		}
		m_configPath = config_file_path;
		m_reverse = reverse;
	} else {

		wstring config_path;

		if (m_basedir.size() < 1) {
			mes = L"cannot read config because base dir is empty";
			return false;
		}

		config_path = m_basedir;

		if (config_path[config_path.size() - 1] != '\\')
			config_path.push_back('\\');

		wstring config_file = config_path + REVERSE_CONFIG_NAME;

		if (_wfopen_s(&fl, &config_file[0], L"rb")) {
			config_file = config_path + CONFIG_NAME;
			if (_wfopen_s(&fl, &config_file[0], L"rb")) {
				mes = L"failed to open config file";
				return false;
			}
			m_reverse = false;
		} else {	
			m_reverse = true;
		}

		m_configPath = config_file;
	}

	File.reset(fl);

	if (fseek(fl, 0, SEEK_END)) {
		mes = L"unable to seek to end of config file";
		return false;
	}

	long filesize = ftell(fl);

	if (filesize > MAX_CONFIG_FILE_SIZE) {
		mes = L"config file is too big";
		return false;
	}

	if (filesize < 1) {
		mes = L"config file is empty";
		return false;
	}

	if (fseek(fl, 0, SEEK_SET)) {
		mes = L"unable to seek to beginning of config file";
		return false;
	}

	char *buf = NULL;

	try {
		buf = new char[filesize + 1];
	} catch (...) {
		buf = NULL;
	}

	if (!buf) {
		mes = L"cannot allocate buffer for reading config file";
		return false;
	}

	size_t len = fread(buf, 1, filesize, fl);

	if (len < 0) {
		mes = L"read error when reading config file";
		return false;
	}

	buf[len] = '\0';

	rapidjson::Document d;

	d.Parse(buf);

	delete[] buf;

	if (!d.IsObject()) {
		mes = L"config file is not valid JSON";
		return false;
	}

	bool bret = true;

	try {

		if (!d.HasMember("EncryptedKey") || !d["EncryptedKey"].IsString()) {
			mes = L"key missing in config file";
			throw (-1);
		}

		rapidjson::Value& v = d["EncryptedKey"];

		if (!base64_decode(v.GetString(), m_encrypted_key, false, true)) {
			mes = L"failed to base64 decode key";
			throw (-1);
		}

		if (!d.HasMember("ScryptObject") || !d["ScryptObject"].IsObject()) {
			mes = L"ScryptObject missing in config file";
			throw (-1);
		}

		rapidjson::Value& scryptobject = d["ScryptObject"];


		if (!base64_decode(scryptobject["Salt"].GetString(), m_encrypted_key_salt, false, true)) {
			mes = L"failed to base64 decode Scrypt Salt";
			throw (-1);
		}

		const char *sstuff[] = { "N", "R", "P", "KeyLen" };

		int i;

		for (i = 0; i < sizeof(sstuff) / sizeof(sstuff[0]); i++) {
			if (scryptobject[sstuff[i]].IsNull() || !scryptobject[sstuff[i]].IsInt()) {
				mes = L"invalid Scrypt object";
				throw (-1);
			}
		}

		m_N = scryptobject["N"].GetInt();
		m_R = scryptobject["R"].GetInt();
		m_P = scryptobject["P"].GetInt();
		int keyLen = scryptobject["KeyLen"].GetInt();

		if (keyLen != 32) {
			mes = L"invalid KeyLen";
			throw(-1);
		}

		m_pKeyBuf = new LockZeroBuffer<unsigned char>(keyLen);

		if (!m_pKeyBuf->IsLocked()) {
			mes = L"failed to lock key buffer";
			throw(-1);
		}

		if (d["Version"].IsNull() || !d["Version"].IsInt()) {
			mes = L"invalid Version";
			throw (-1);
		}

		rapidjson::Value& version = d["Version"];

		m_Version = version.GetInt();

		if (d.HasMember("VolumeName") && !d["VolumeName"].IsNull() && d["VolumeName"].IsString()) {
			rapidjson::Value& volume_name = d["VolumeName"];
			string utf8name;
			utf8name = volume_name.GetString();
			wstring storage;
			const WCHAR *vname = utf8_to_unicode(&utf8name[0], storage);
			if (vname)
				m_VolumeName = vname;
		}

		if (d.HasMember("FeatureFlags") && !d["FeatureFlags"].IsNull() && d["FeatureFlags"].IsArray()) {

			rapidjson::Value& flags = d["FeatureFlags"];

			for (rapidjson::Value::ConstValueIterator itr = flags.Begin(); itr != flags.End(); ++itr) {
				if (itr->IsString()) {
					if (!strcmp(itr->GetString(), "PlaintextNames")) {
						m_PlaintextNames = true;
					} else if (!strcmp(itr->GetString(), "DirIV")) {
						m_DirIV = true;
					} else if (!strcmp(itr->GetString(), "EMENames")) {
						m_EMENames = true;
					} else if (!strcmp(itr->GetString(), "GCMIV128")) {
						m_GCMIV128 = true;
					} else if (!strcmp(itr->GetString(), "LongNames")) {
						m_LongNames = true;
					} else if (!strcmp(itr->GetString(), "AESSIV")) {
						m_AESSIV = true;
					} else if (!strcmp(itr->GetString(), "Raw64")) {
						m_Raw64 = true;
					} else if (!strcmp(itr->GetString(), "HKDF")) {
						m_HKDF = true;
					} else {
						wstring wflag;
						if (utf8_to_unicode(itr->GetString(), wflag)) {
							mes = L"unkown feature flag: ";
							mes += wflag;
						} else {
							mes = L"unable to convert unkown flag to unicode";
						}
						throw(-1);
					}
				}
			}
		}

		
	} catch (...) {
		bret = false;
	}

	return bret;
}

bool CryptConfig::init_serial(CryptContext *con)
{
	BYTE diriv[DIR_IV_LEN];

	this->m_serial = 0;

	if (!m_reverse && this->DirIV() && get_dir_iv(con, &this->m_basedir[0], diriv)) {

		this->m_serial = *(DWORD*)diriv;

	}

	if (!this->m_serial) {

		wstring str = L"XjyG7KDokdqpxtjUh6oCVJ92FmPFJ1Fg"; // salt

		str += this->m_basedir;

		BYTE sum[32];

		string utf8;

		if (unicode_to_utf8(&str[0], utf8)) {

			if (sha256(utf8, sum))
				this->m_serial = *(DWORD*)sum;
		}
	}

	if (!this->m_serial) // ultimate fall-back
		this->m_serial = DEFAULT_VOLUME_SERIAL_NUMBER;

	return true;
}

bool CryptConfig::write_volume_name()
{
	bool bret = true;

	try {
		wstring vol = m_VolumeName;

		string volume_name_utf8_enc;

		if (vol.size() > 0) {
			if (vol.size() > MAX_VOLUME_NAME_LENGTH)
				vol.erase(MAX_VOLUME_NAME_LENGTH, wstring::npos);
			if (!encrypt_string_gcm(vol, GetGcmContentKey(), volume_name_utf8_enc)) {
				throw(-1);
			}
		}

		if (m_configPath.size() < 1)
			throw(-1);

		wstring config_path = m_configPath;

		const WCHAR *path = &config_path[0];

		auto File = cppcryptfs::unique_ptr<FILE>(_wfopen_s, fclose, path, L"rb");
		auto fl = File.get();

		if (!fl)
			throw(-1);

		if (fseek(fl, 0, SEEK_END))
			throw(-1);

		long filesize = ftell(fl);

		if (filesize < 0)
			throw(-1);

		if (filesize > MAX_CONFIG_FILE_SIZE)
			throw(-1);

		if (fseek(fl, 0, SEEK_SET))
			throw(-1);

		std::vector<char> buf(filesize+1);

		size_t len = fread(&buf[0], 1, filesize, fl);

		File.reset();

		if (len < 0)
			throw(-1);

		buf[len] = '\0';

		rapidjson::Document d;

		d.Parse(&buf[0]);

		rapidjson::Value vname(volume_name_utf8_enc.c_str(), d.GetAllocator());

		if (d.HasMember("VolumeName")) {
			d["VolumeName"] = vname;
		} else {
			d.AddMember("VolumeName", vname, d.GetAllocator());
		}
		wstring tmp_path = config_path;
		tmp_path += L".tmp";

		auto fl1 = cppcryptfs::unique_ptr<FILE>(_wfopen_s, fclose, tmp_path.c_str(), L"wb");
		if (!fl1)
			throw (-1);
		const size_t writeBuffer_len = 128 * 1024;
		std::vector<char> writeBuffer(writeBuffer_len);
		rapidjson::FileWriteStream os(fl1.get(), &writeBuffer[0], writeBuffer_len);
		rapidjson::PrettyWriter<rapidjson::FileWriteStream> writer(os);
		d.Accept(writer);
		
		CryptConfig test_cfg;

		fl1.reset();

		auto deleteFile = cppcryptfs::unique_rsc([](auto s){return s;}, DeleteFile,tmp_path.c_str() ) ;

		try {
			wstring config_err_mes;
			if (!test_cfg.read(config_err_mes, tmp_path.c_str())) {
				throw(-1);
			}
			if (!test_cfg.check_config(config_err_mes)) {
				throw(-1);
			}
			if (m_encrypted_key != test_cfg.m_encrypted_key ||
				m_encrypted_key_salt != test_cfg.m_encrypted_key_salt ||
				m_N != test_cfg.m_N || m_R != test_cfg.m_R || m_P != test_cfg.m_P) {
				throw(-1);
			}
		} catch (...) {
			throw (-1);
		}

		DWORD dwAttr = GetFileAttributes(config_path.c_str());

		if (dwAttr == INVALID_FILE_ATTRIBUTES) {
			throw (-1);
		}

		bool bWasReadOnly = false;

		if (dwAttr & FILE_ATTRIBUTE_READONLY) {

			bool bWasReadOnly = true;

			dwAttr &= ~FILE_ATTRIBUTE_READONLY;

			if (!SetFileAttributes(&config_path[0], dwAttr)) {
				throw (-1);
			}
		}

		if (!MoveFileEx(&tmp_path[0], &config_path[0], MOVEFILE_REPLACE_EXISTING)) {
			throw (-1);
		}

		deleteFile.release();

		if (bWasReadOnly) {
			dwAttr = GetFileAttributes(&config_path[0]);

			if (dwAttr == INVALID_FILE_ATTRIBUTES) {
				throw (-1);
			}

			if (!(dwAttr & FILE_ATTRIBUTE_READONLY)) {
				dwAttr |= FILE_ATTRIBUTE_READONLY;

				if (!SetFileAttributes(&config_path[0], dwAttr)) {
					throw (-1);
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

bool CryptConfig::check_config(wstring& mes)
{
	mes = L"";

	if (m_Version != 2)
		mes += L"Only version 2 is supported\n";
	
	if (!m_DirIV && !m_PlaintextNames) 
		mes += L"DirIV is required unless PlaintextNames is specified\n";

	if (!m_EMENames && !m_PlaintextNames)
		mes += L"EMENames is required unless PlaintextNames is specified\n";
	
	if (!m_GCMIV128) 
		mes += L"GCMIV128 must be specified\n";

	if (m_reverse && !m_AESSIV)
		mes += L"reverse mode is being used but AESSIV not specfied\n";
		
	return mes.size() == 0;
}

bool CryptConfig::decrypt_key(LPCTSTR password)
{

	bool bret = true;

	void *context = NULL;

	try {
		if (m_encrypted_key.size() == 0 || m_encrypted_key_salt.size() == 0 || GetMasterKeyLength() == 0)
			return false;

		LockZeroBuffer<char> pass_buf(4*MAX_PASSWORD_LEN+1);

		if (!pass_buf.IsLocked())
			throw (-1);

		const char *pass = unicode_to_utf8(password, pass_buf.m_buf, pass_buf.m_len-1);

		if (!pass) {
			throw (-1);
		}

		LockZeroBuffer<unsigned char> pwkey(GetMasterKeyLength());

		LockZeroBuffer<unsigned char> pwkeyHKDF(GetMasterKeyLength());

		if (!pwkey.IsLocked())
			throw(-1);

		if (m_HKDF && !pwkeyHKDF.IsLocked())
			throw(-1);

		int result = EVP_PBE_scrypt(pass, strlen(pass), &m_encrypted_key_salt[0], 
			m_encrypted_key_salt.size(), m_N, m_R, m_P, SCRYPT_MB * 1024 * 1024, pwkey.m_buf,
			GetMasterKeyLength());

		if (result != 1)
			throw (-1);

		unsigned char adata[8];

		const int adata_len = sizeof(adata);

		memset(adata, 0, adata_len);

		int ivlen = m_HKDF ? HKDF_MASTER_IV_LEN : ORIG_MASTER_IV_LEN;

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

		if (m_HKDF) {
			if (!hkdfDerive(pwkey.m_buf, pwkey.m_len, pwkeyHKDF.m_buf, pwkeyHKDF.m_len, hkdfInfoGCMContent))
				throw(-1);
		}

		int ptlen = decrypt(ciphertext, ciphertext_len, adata, adata_len, tag, m_HKDF ? pwkeyHKDF.m_buf : pwkey.m_buf, iv, m_pKeyBuf->m_buf, context);

		if (ptlen != MASTER_KEY_LEN)
			throw (-1);

		// need to do it unconditionally because we use it for other things besides file data
		if (!this->InitGCMContentKey(this->GetMasterKey(), this->m_HKDF)) {
			throw(-1);
		}

		if (m_VolumeName.size() > 0) {
			string vol;
			if (unicode_to_utf8(&m_VolumeName[0], vol)) {
				if (!decrypt_string_gcm(vol, GetGcmContentKey(), m_VolumeName))
					m_VolumeName = L"";
				if (m_VolumeName.size() > MAX_VOLUME_NAME_LENGTH)
					m_VolumeName.erase(MAX_VOLUME_NAME_LENGTH, wstring::npos);
			} else {
				m_VolumeName = L"";
			}
		}

	} catch (...) {
		bret = false;
	}

	if (context)
		free_crypt_context(context);

	return bret;
}



bool CryptConfig::create(const WCHAR *path, const WCHAR *specified_config_file_path, const WCHAR *password, bool eme, bool plaintext, bool longfilenames, bool siv, bool reverse, const WCHAR *volume_name, wstring& error_mes)
{

	LockZeroBuffer<char> utf8pass(256);
	if (!utf8pass.IsLocked()) {
		error_mes = L"utf8 pass is not locked";
		return false;
	}

	if (specified_config_file_path && *specified_config_file_path == '\0')
		specified_config_file_path = NULL;

	m_basedir = path;

	bool bret = true;

	LockZeroBuffer<unsigned char> pwkey(MASTER_KEY_LEN);
	LockZeroBuffer<unsigned char> pwkeyHKDF(MASTER_KEY_LEN);

	if (!pwkey.IsLocked() || !pwkeyHKDF.IsLocked()) {
		error_mes = L"pw key not locked";
		return false;
	}

	void *context = NULL;

	unsigned char *encrypted_key = NULL;

	if (eme)
		m_EMENames = TRUE;
	else if (plaintext)
		m_PlaintextNames = TRUE;

	if (!m_PlaintextNames)
		m_LongNames = longfilenames;

	if (siv)
		m_AESSIV = true;

	// Raw64 and HKDF default to true
	m_Raw64 = true;
	m_HKDF = true;

	if (reverse)
		m_reverse = true;

	try {

		wstring config_path;

		if (specified_config_file_path) {
			config_path = specified_config_file_path;
		} else {

			config_path = m_basedir;

			if (config_path[config_path.size() - 1] != '\\')
				config_path.push_back('\\');

			config_path += m_reverse ? REVERSE_CONFIG_NAME : CONFIG_NAME;

		}

		if (m_reverse && !m_AESSIV) {
			error_mes = L"AES256-SIV must be used with Reverse\n";
			throw(-1);
		}

		if (m_reverse) {
			if (PathFileExists(&config_path[0])) {
				if (specified_config_file_path) {
					error_mes = config_path + L" already exists.  Please remove it and try again.";
				} else {
					error_mes = config_path + L" (normally a hidden file) already exists.  Please remove it and try again.";
				}
				throw(-1);
			}
		} else {
			if (!can_delete_directory(&m_basedir[0], TRUE)) {
				error_mes = L"the directory is not empty\n";
				throw(-1);
			}
		}	

		m_encrypted_key_salt.resize(SALT_LEN);

		if (!get_sys_random_bytes(&m_encrypted_key_salt[0], SALT_LEN)) {
			error_mes = L"get random bytes for salt failed\n";
			throw(-1);
		}

		m_N = 65536;
		m_R = 8;
		m_P = 1;

		m_pKeyBuf = new LockZeroBuffer<unsigned char>(DEFAULT_KEY_LEN);

		if (!m_pKeyBuf->IsLocked()) {
			error_mes = L"cannot lock key buffer\n";
			throw(-1);
		}
		
		m_Version = 2;
		m_DirIV = !m_PlaintextNames;
		
		if (!unicode_to_utf8(password, utf8pass.m_buf, utf8pass.m_len - 1)) {
			error_mes = L"cannot convert password to utf-8\n";
			throw(-1);
		}
	

		int result = EVP_PBE_scrypt(utf8pass.m_buf, strlen(utf8pass.m_buf), &m_encrypted_key_salt[0], 
			m_encrypted_key_salt.size(), m_N, m_R, m_P, SCRYPT_MB * 1024 * 1024, pwkey.m_buf,
			GetMasterKeyLength());

		if (result != 1) {
			error_mes = L"key derivation failed\n";
			throw(-1);
		}

		if (!hkdfDerive(pwkey.m_buf, pwkey.m_len, pwkeyHKDF.m_buf, pwkeyHKDF.m_len, hkdfInfoGCMContent)) {
			error_mes = L"unable to perform hkdf on pw key";
			throw(-1);
		}

		_ASSERT(m_HKDF);
		unsigned char iv[HKDF_MASTER_IV_LEN];

		if (!get_sys_random_bytes(iv, sizeof(iv))) {
			error_mes = L"unable to generate iv\n";
			throw(-1);
		}

		unsigned char adata[8];

		const int adata_len = sizeof(adata);

		memset(adata, 0, adata_len);

		if (!get_sys_random_bytes(m_pKeyBuf->m_buf, GetMasterKeyLength())) {
			error_mes = L"unable to generate master key\n";
			throw(-1);
		}

		if (!InitGCMContentKey(GetMasterKey(), m_HKDF)) {
			error_mes = L"unable to init gcm content key for volume name";
			throw(-1);
		}

		string volume_name_utf8;

		if (volume_name && wcslen(volume_name)) {
			wstring vol = volume_name;
			if (vol.size() > MAX_VOLUME_NAME_LENGTH)
				vol.erase(MAX_VOLUME_NAME_LENGTH, wstring::npos);
			if (!encrypt_string_gcm(vol, GetGcmContentKey(), volume_name_utf8)) {
				error_mes = L"cannot encrypt volume name\n";
				throw(-1);
			}
		}

		_ASSERT(m_HKDF);
		context = get_crypt_context(HKDF_MASTER_IV_LEN, AES_MODE_GCM);

		if (!context) {
			error_mes = L"unable to get gcm context\n";
			throw(-1);
		}

		_ASSERT(m_HKDF);
		encrypted_key = new unsigned char[GetMasterKeyLength() + HKDF_MASTER_IV_LEN + BLOCK_TAG_LEN];

		memcpy(encrypted_key, iv, sizeof(iv));

		_ASSERT(m_HKDF);
		int ctlen = encrypt(m_pKeyBuf->m_buf, GetMasterKeyLength(), adata, sizeof(adata), pwkeyHKDF.m_buf, iv, (encrypted_key + sizeof(iv)), encrypted_key + sizeof(iv) + GetMasterKeyLength(), context);

		if (ctlen < 1) {
			error_mes = L"unable to encrypt master key\n";
			throw(-1);
		}

		string storage;

		_ASSERT(m_HKDF);
		const char *base64_key = base64_encode(encrypted_key, GetMasterKeyLength() + HKDF_MASTER_IV_LEN + BLOCK_TAG_LEN, storage, false, true);

		if (!base64_key) {
			error_mes = L"unable to base64 encode key\n";
			throw(-1);
		}

		auto File = cppcryptfs::unique_ptr<FILE>(_wfopen_s, fclose, &config_path[0], L"wb");
		auto fl = File.get();

		if (!fl) {
			error_mes = L"cannot create config file\n";
			throw(-1);
		}

		if (!fl) {
			error_mes = L"unable to open config file for writing\n";
			throw(-1);
		}

		fprintf(fl, "{\n");

		wstring prodName, prodVersion, prodCopyright;

		if (GetProductVersionInfo(prodName, prodVersion, prodCopyright)) {
			string creator_str;
			wstring wcreator = prodName + L" v" + prodVersion;
			const char *creator = unicode_to_utf8(&wcreator[0], creator_str);
			if (creator)
				fprintf(fl, "\t\"Creator\": \"%s\",\n", creator);
		}

		fprintf(fl, "\t\"EncryptedKey\": \"%s\",\n", base64_key);

		const char *base64_salt = base64_encode(&m_encrypted_key_salt[0], (DWORD)m_encrypted_key_salt.size(), storage, false, true);
		fprintf(fl, "\t\"ScryptObject\": {\n");
		fprintf(fl, "\t\t\"Salt\": \"%s\",\n", base64_salt);
		fprintf(fl, "\t\t\"N\": %d,\n", m_N);
		fprintf(fl, "\t\t\"R\": %d,\n", m_R);
		fprintf(fl, "\t\t\"P\": %d,\n", m_P);
		fprintf(fl, "\t\t\"KeyLen\": %d\n", GetMasterKeyLength());
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
		if (m_AESSIV)
			fprintf(fl, "\t\t\"AESSIV\",\n");
		if (m_HKDF)
			fprintf(fl, "\t\t\"HKDF\",\n");
		if (m_Raw64)
			fprintf(fl, "\t\t\"Raw64\",\n");
		fprintf(fl, "\t\t\"GCMIV128\"\n");
		fprintf(fl, "\t]\n");
		fprintf(fl, "}\n");

		DWORD attr = GetFileAttributesW(&config_path[0]);
		if (attr != INVALID_FILE_ATTRIBUTES) {
			attr |= FILE_ATTRIBUTE_READONLY | (m_reverse && !specified_config_file_path ? FILE_ATTRIBUTE_HIDDEN : 0);
			SetFileAttributes(&config_path[0], attr);
		}

		if (m_DirIV && !m_reverse) {
			if (!create_dir_iv(NULL, &m_basedir[0])) {
				error_mes = L"cannot create diriv file\n";
				throw(-1);
			}
		}

	} catch (...) {

		if (error_mes.size() < 1)
			error_mes = L"memory allocation failure\n";

		bret = false;
	}

	if (encrypted_key) {
		delete[] encrypted_key;
	}

	if (context)
		free_crypt_context(context);

	return bret;
}

bool CryptConfig::InitGCMContentKey(const BYTE *key, bool hkdf)
{
	if (!hkdf)
		return true;

	m_pGcmContentKey = new LockZeroBuffer<BYTE>(MASTER_KEY_LEN);

	if (!m_pGcmContentKey->IsLocked())
		return false;

	if (hkdf) {
		if (!hkdfDerive(key, MASTER_KEY_LEN, m_pGcmContentKey->m_buf, m_pGcmContentKey->m_len, hkdfInfoGCMContent))
			return false;
	}

	return true;
}

