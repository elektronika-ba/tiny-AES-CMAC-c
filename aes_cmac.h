#ifndef _AES_CMAC_H_
#define _AES_CMAC_H_

#include <stdint.h>

struct AES_CMAC_ctx
{
	void (*aes_cipher_callback)(uint8_t*);
};

void AES_CMAC_init_ctx(struct AES_CMAC_ctx* ctx, void* aes_cipher_callback);
void AES_CMAC_digest(const struct AES_CMAC_ctx* ctx, uint8_t* input, uint16_t length, uint8_t* result);

#endif // _AES_CMAC_H_
