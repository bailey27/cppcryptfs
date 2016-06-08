#ifndef _UTIL_H_INCLUDED

#define _UTIL_H_INCLUDED 1

#include <windows.h>
#include <vector>


const char *
unicode_to_utf8(const WCHAR *unicode_str, char *buf, int buflen);

const char *
unicode_to_utf8(const WCHAR *unicode_str, std::string& storage);

const WCHAR *
utf8_to_unicode(const char *utf8_str, std::wstring& storage);

bool
base64_decode(const char *str, std::vector<unsigned char>& storage, bool urlTransform = true);

const char *
base64_encode(const BYTE *data, DWORD datalen, std::string& storage, bool urlTransform = true);


BOOL
IsBigEndianMachine();


template<typename T>
T swapBytesVal(T x);

template<typename T>
T MakeBigEndian(T n);

template<typename T>
T MakeBigEndianNative(T n);

bool read_password(WCHAR *pwbuf, int pwbuflen, const WCHAR *prompt = NULL);

bool
get_random_bytes(unsigned char *buf, DWORD len);

bool get_sys_random_bytes(unsigned char *buf, DWORD len);

#endif