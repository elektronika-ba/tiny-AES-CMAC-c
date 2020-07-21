### Tiny AES CMAC in C

This is an implementation of the [AES CMAC](https://tools.ietf.org/html/rfc4493) algorithm written in C.

I used it with [tiny-AES-c](https://github.com/kokke/tiny-AES-c) in AES256 mode.

The API is very simple and looks like this:

```C
void AES_CMAC_init_ctx(struct AES_CMAC_ctx* ctx, void* aes_cipher_callback);
void AES_CMAC_digest(const struct AES_CMAC_ctx* ctx, uint8_t* input, uint16_t length, uint8_t* result);
```

Usage example:

```C
/* your callback function that performs the actual AES encryption */
void aes_cmac_encrypt(uint8_t* data) {
  AES_ECB_encrypt(&cmac_ctx, data); // <-- this is the *external* AES encryption function with its own logic. you can use tiny-AES-c library from kokke
}

/* create AES CMAC context used to generate the CMAC */
struct AES_CMAC_ctx aes_cmac_ctx;
/* provide the CMAC library with AES encryption callback function that will perform the actual AES encryption */
AES_CMAC_init_ctx(&aes_cmac_ctx, &aes_cmac_encrypt);

/* message to generate the CMAC from */
uint8_t message[] = { 0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A };

/* generate the CMAC */
uint8_t cmac[16];
AES_CMAC_digest(&aes_cmac_ctx, message, sizeof(message), cmac);

/* print out the resulting tag */
for (uint8_t i = 0; i < 16; i++) {
  printf("%02X ", cmac[i]);
}
```


Verified against test vectors from https://csrc.nist.gov/CSRC/media/Projects/Block-Cipher-Techniques/documents/BCM/proposed-modes/omac/omac-ad.pdf
