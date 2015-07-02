#include "Base64.h"


int Base64Encode(char **dest, const char *src, unsigned int slen){

	BIO *bio, *b64;
	BUF_MEM *bufferPtr;
	int numBytesEncoded = 0;

	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new(BIO_s_mem());
	bio = BIO_push(b64, bio);

	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
	BIO_write(bio, src, slen);
	BIO_flush(bio);
	BIO_get_mem_ptr(bio, &bufferPtr);
	BIO_set_close(bio, BIO_NOCLOSE);
	BIO_free_all(bio);

	*dest = (unsigned char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (*bufferPtr).length + 1);
	if (*dest == NULL) return false;

	strncpy_s(*dest, (*bufferPtr).length + 1, (*bufferPtr).data, (*bufferPtr).length);

	numBytesEncoded = (*bufferPtr).length + 1;

	if (bufferPtr) {
		free(bufferPtr);
		bufferPtr = NULL;
	}

	return numBytesEncoded;

	return true;
}

int Base64Decode(char **dest, const char *src){

	unsigned int dlen = 0;
	BIO *bio, *b64;

	unsigned int decode_length = countDecodedLength(src);

	*dest = (unsigned char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, decode_length + 1);
	if (*dest == NULL) return false;

	bio = BIO_new_mem_buf((char*)src, -1);
	b64 = BIO_new(BIO_f_base64());
	bio = BIO_push(b64, bio);

	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
	dlen = BIO_read(bio, *dest, strlen(src));
	if (dlen != decode_length){
		if (dest){
			HeapFree(GetProcessHeap(), 0, dest);
			dest = NULL;
		}
		BIO_free_all(bio);
		return false;
	}
	BIO_free_all(bio);

	return decode_length;
}

unsigned int countDecodedLength(const char *encoded) {

	unsigned int len = strlen(encoded), padding = 0;

	if (encoded[len - 1] == '=' && encoded[len - 2] == '=')
		padding = 2;
	else if (encoded[len - 1] == '=')
		padding = 1;

	return (len * 3) / 4 - padding;
}
