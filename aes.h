#pragma once

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <string.h>
#include <stdio.h>

#define AES_KEYLEN 256                
#define AES_KEYBYTES (AES_KEYLEN / 8) 
#define AES_BLOCK_SIZE 16             


typedef struct
{
    unsigned char key[AES_KEYBYTES];  // Key for AES operations
    unsigned char iv[AES_BLOCK_SIZE]; // Initialization vector for CBC mode
} AES_CTX;

// Initializes AES context for encryption and decryption
int aes_init(AES_CTX *ctx, const unsigned char *key_data, int key_data_len, const unsigned char *salt);

// Encrypts plaintext using AES CBC mode
void aes_encrypt(AES_CTX *ctx, const unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext, int *ciphertext_len);

// Decrypts ciphertext using AES CBC mode
int aes_decrypt(AES_CTX *ctx, const unsigned char *ciphertext, int ciphertext_len, unsigned char *plaintext, int *plaintext_len);

// Compute HMAC using SHA-256
void hmac_sha256(const unsigned char *data, int data_len, unsigned char *key, int key_len, unsigned char *digest);
