#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "aes_cmac.h"

/*
	Initialize context for AES CMAC.
*/
void AES_CMAC_init_ctx(struct AES_CMAC_ctx* ctx, void* aes_cipher_callback) {
	ctx->aes_cipher_callback = aes_cipher_callback;
}

/*
	Left-shift entire buffer once. Buffer is "length" bytes wide.
*/
static void left_shift_buffer(uint8_t* input, uint8_t* output, uint8_t length) {
	uint8_t overflow = 0;
	uint8_t i;

	for (i = length; i > 0; i--)
	{
		output[i - 1] = input[i - 1] << 1;
		output[i - 1] |= overflow;
		overflow = (input[i - 1] & 0x80) ? 1 : 0;
	}
}

/*
	XOR buff1 and buff2, fill result in out_buff. Length of buffers buff1 and buff2 should be equal,
	and length(out_buff) >= length(buff*)
	One of in_buff1 and in_buff2 can be the same array as out_buff.
*/
static void xor_buffers(uint8_t* in_buff1, uint8_t* in_buff2, uint8_t* out_buff, uint8_t length) {
	do {
		uint8_t in_val1 = *in_buff1;
		uint8_t in_val2 = *in_buff2;

		*out_buff = in_val1 ^ in_val2;

		out_buff++;
		in_buff1++;
		in_buff2++;
	} while (--length);
}

/*
   The subkey generation algorithm, Generate_Subkey(), takes a secret
   key, K, which is just the key for AES-128.
   The outputs of the subkey generation algorithm are two subkeys, K1
   and K2.  We write (K1,K2) := Generate_Subkey(K).
   KEY, out_K1, out_K2 must be 16 bytes long arrays.
*/
static void generate_cmac_sub_keys(const struct AES_CMAC_ctx* ctx, uint8_t* out_K1, uint8_t* out_K2) {
	// Step 1.
	memset(out_K2, 0, 16);
	ctx->aes_cipher_callback(out_K2);

	// Step 2.
	left_shift_buffer(out_K2, out_K1, 16);
	if (out_K2[0] & 0x80) {
		out_K1[15] = out_K1[15] ^ 0x87;
	}

	// Step 3.
	left_shift_buffer(out_K1, out_K2, 16);
	if (out_K1[0] & 0x80) {
		out_K2[15] = out_K2[15] ^ 0x87;
	}

	// Step 4. (return K1, K2) - already in provided buffers out_K1 and out_K2
}

/*
	Generate CMAC from provided input "buffer" of length "length", into "result" 16 bytes wide buffer.
*/
void AES_CMAC_digest(const struct AES_CMAC_ctx* ctx, uint8_t* input, uint16_t length, uint8_t* result) {
	uint8_t K1[16], K2[16];

	// STEP 1.
	generate_cmac_sub_keys(ctx, K1, K2);

	// STEP 2.
	uint16_t n = (length + 15) / 16; // n is number of rounds
	uint8_t lenMod16 = length % 16; // will need later (optimization for speed)

	// STEP 3.
	uint8_t flag = 0; // assume last block is not complete block
	if (n == 0) {
		n = 1;
	}
	else if (lenMod16 == 0) {
		flag = 1; // last block is a complete block
	}

	// STEP 4.
	uint8_t* M_last;
	uint8_t index = 16 * (n - 1);
	// last block is complete block
	if (flag) {
		M_last = &K2[0]; // using the same RAM space for M_last as that of K2 - size optimization
		xor_buffers(&input[index], K1, M_last, 16);
	}
	else {
		M_last = &K1[0]; // using the same RAM space for M_last as that of K1 - size optimization

		// padding input and xoring with K2 at the same time
		for (uint8_t j = 0; j < 16; j++) {
			uint8_t temp = 0x00; // assume padding with 0x00
			if (j < lenMod16) { // we have this byte index in input - take it
				temp = input[index + j];
			}
			else if (j == lenMod16) { // first missing byte byte of input is padded with 0x80
				temp = 0x80;
			}

			M_last[j] = temp ^ K2[j];
		}
	}

	// STEP 5.
	memset(result, 0, 16);

	// STEP 6.
	for (uint8_t i = 0; i < n-1; i++) {
		xor_buffers(result, &input[16 * i], result, 16); // Y := Mi (+) X
		ctx->aes_cipher_callback(result); // X := AES-128(KEY, Y);
	}

	xor_buffers(result, M_last, result, 16);
	ctx->aes_cipher_callback(result);

	// Step 7. return T (already done in provided "result" buffer)
}
