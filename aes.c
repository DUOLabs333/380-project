#include "aes.h"

// Initializes AES encryption and decryption contexts
int aes_init(AES_CTX *ctx, const unsigned char *key_data, int key_data_len, const unsigned char *salt)
{
    unsigned char key[AES_KEYBYTES + AES_BLOCK_SIZE]; // Key + IV
    // Generate key and IV using EVP_BytesToKey
    if (!EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), salt, key_data, key_data_len, 5, key, ctx->iv))
    {
        fprintf(stderr, "Key generation failed.\n");
        return 0;
    }
    return 1;
}

// Encrypts plaintext using AES CBC mode
void aes_encrypt(const unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext)
{
    AES_CTX ctx;
    // Initialize the AES context with the appropriate key and IV
    aes_init(&ctx, your_key_data, key_data_len, your_salt);

    EVP_CIPHER_CTX *e_ctx = EVP_CIPHER_CTX_new();
    unsigned char iv_copy[AES_BLOCK_SIZE];
    memcpy(iv_copy, ctx.iv, AES_BLOCK_SIZE);
    EVP_EncryptInit_ex(e_ctx, EVP_aes_256_cbc(), NULL, ctx.key, iv_copy);
    int len = 0;
    EVP_EncryptUpdate(e_ctx, ciphertext, &len, plaintext, plaintext_len);
    int ciphertext_len = len; // Calculate ciphertext length
    EVP_EncryptFinal_ex(e_ctx, ciphertext + len, &len);
    ciphertext_len += len; // Add the final block length
    EVP_CIPHER_CTX_free(e_ctx);
}

// Decrypts ciphertext using AES CBC mode
void aes_decrypt(const unsigned char *key, int keylen, const unsigned char *ciphertext, int ciphertext_len, unsigned char *plaintext, int *plaintext_len)
{
    AES_CTX ctx;
    // Initialize the AES context with the provided key and IV
    aes_init(&ctx, key, keylen, your_salt);

    EVP_CIPHER_CTX *d_ctx = EVP_CIPHER_CTX_new();
    unsigned char iv_copy[AES_BLOCK_SIZE];
    memcpy(iv_copy, ctx.iv, AES_BLOCK_SIZE);
    EVP_DecryptInit_ex(d_ctx, EVP_aes_256_cbc(), NULL, ctx.key, iv_copy);
    int len = 0;
    EVP_DecryptUpdate(d_ctx, plaintext, &len, ciphertext, ciphertext_len);
    *plaintext_len = len;
    int ret = EVP_DecryptFinal_ex(d_ctx, plaintext + len, &len);
    if (ret > 0)
        *plaintext_len += len;
    else
        *plaintext_len = 0; // Handle decryption error
    EVP_CIPHER_CTX_free(d_ctx);
}

// Computes HMAC using SHA-256
void hmac_sha256(const unsigned char *data, int data_len, unsigned char *key, int key_len, unsigned char *digest)
{
    unsigned int digest_len;
    HMAC(EVP_sha256(), key, key_len, data, data_len, digest, &digest_len);
}
