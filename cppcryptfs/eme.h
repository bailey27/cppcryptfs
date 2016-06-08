#pragma once

#include <windows.h>

#include "cryptdefs.h"

#include "openssl/aes.h"

class lCacheContainer;

struct struct_EmeCryptContext {
	BYTE *key;
	lCacheContainer *lc;
};

typedef struct struct_EmeCryptContext EmeCryptContext;

class lCacheContainer {
public:
	AES_KEY encryption_key;
	AES_KEY decryption_key;

	LPBYTE *LTable;
	bool enabled;

	void init(EmeCryptContext *eme_context);
	lCacheContainer();
	virtual ~lCacheContainer();
};

extern "C" {
	BYTE* EmeTransform(EmeCryptContext *eme_context, BYTE *T, BYTE *P, int len, bool direction);
};
