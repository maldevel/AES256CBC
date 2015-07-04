#include "AES256CBC.h"


bool GenerateKeys(const unsigned char *password, int plen, unsigned char *aesSalt, unsigned char *aesKey, unsigned char *aesIV){

	if (RAND_bytes(aesSalt, 8) == 0)
		return false;

	aesSalt[PKCS5_SALT_LEN] = '\0';

	if (!EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), aesSalt, password, plen, AES_ROUNDS, aesKey, aesIV))
		return false;

	return true;
}


int Encrypt(char **cipher, const char *plain, int plen, unsigned char *aesKey, unsigned char *aesIV){

	EVP_CIPHER_CTX *ctx;
	unsigned char *cipher_tmp = { 0 };
	int len = 0, cipherTextLen = 0, retvalue = 0;

	if (!(ctx = EVP_CIPHER_CTX_new())) {
		return 0;
	}

	if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aesKey, aesIV)) {
		if (ctx) EVP_CIPHER_CTX_free(ctx);
		return 0;
	}

	cipher_tmp = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, plen + 16);
	if (cipher_tmp == NULL) return 0;

	if (1 != EVP_EncryptUpdate(ctx, cipher_tmp, &len, plain, plen - 1)) {
		if (ctx) EVP_CIPHER_CTX_free(ctx);
		if (cipher_tmp) {
			HeapFree(GetProcessHeap(), 0, cipher_tmp);
			cipher_tmp = NULL;
		}
		return 0;
	}

	cipherTextLen = len;

	if (1 != EVP_EncryptFinal_ex(ctx, cipher_tmp + len, &len)) {
		if (ctx) EVP_CIPHER_CTX_free(ctx);
		if (cipher_tmp) {
			HeapFree(GetProcessHeap(), 0, cipher_tmp);
			cipher_tmp = NULL;
		}
		return 0;
	}

	cipherTextLen += len;

	if (ctx) EVP_CIPHER_CTX_free(ctx);

	retvalue = cipherTextLen;

	cipher_tmp[cipherTextLen] = '\0';

	if (cipherTextLen > 0)
		retvalue = Base64Encode(cipher, cipher_tmp, cipherTextLen + 1);

	if (cipher_tmp) {
		HeapFree(GetProcessHeap(), 0, cipher_tmp);
		cipher_tmp = NULL;
	}

	return retvalue;
}


int Decrypt(char **plain, const char *cipher, int clen, unsigned char *aesKey, unsigned char *aesIV){

	EVP_CIPHER_CTX *ctx;
	int len = 0, b64DecodedLen = 0, plainTextLen = 0;
	unsigned char *plain_tmp = { 0 };

	b64DecodedLen = Base64Decode(&plain_tmp, cipher);
	if (b64DecodedLen == 0) return 0;

	if (!(ctx = EVP_CIPHER_CTX_new())) {
		if (plain_tmp) {
			HeapFree(GetProcessHeap(), 0, plain_tmp);
			plain_tmp = NULL;
		}
		return 0;
	}

	if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aesKey, aesIV)){
		if (ctx) EVP_CIPHER_CTX_free(ctx);
		if (plain_tmp) {
			HeapFree(GetProcessHeap(), 0, plain_tmp);
			plain_tmp = NULL;
		}
		return 0;
	}

	*plain = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, b64DecodedLen);
	if (*plain == NULL) return 0;

	if (1 != EVP_DecryptUpdate(ctx, *plain, &len, plain_tmp, b64DecodedLen - 1)){
		if (ctx) EVP_CIPHER_CTX_free(ctx);
		if (plain_tmp) {
			HeapFree(GetProcessHeap(), 0, plain_tmp);
			plain_tmp = NULL;
		}
		if (plain) {
			HeapFree(GetProcessHeap(), 0, plain);
			plain = NULL;
		}
		return 0;
	}

	if (plain_tmp) {
		HeapFree(GetProcessHeap(), 0, plain_tmp);
		plain_tmp = NULL;
	}

	plainTextLen = len;

	if (1 != EVP_DecryptFinal_ex(ctx, *plain + len, &len)){
		if (ctx) EVP_CIPHER_CTX_free(ctx);
		if (plain) {
			HeapFree(GetProcessHeap(), 0, plain);
			plain = NULL;
		}
		return 0;
	}

	plainTextLen += len;
	*(*plain + plainTextLen) = '\0';

	if (ctx) EVP_CIPHER_CTX_free(ctx);

	return plainTextLen;
}
