
#pragma once

enum { ECB=0, CBC=1, CFB=2 };

void AES_SetIV(unsigned char *pIV);
void AES_SetKey(unsigned char *pAESKey);
//void AES_CipherBlock(unsigned char *pPlainText, unsigned char *pCiphered);
//void AES_DeCipherBlock(unsigned char *pCiphered, unsigned char *pPlainText);
size_t AES_Encrypt(unsigned char* in, size_t inn, unsigned char* result, size_t outn, bool bChaining = false, int iMode = ECB);
//void AES_Encrypt(unsigned char* in, unsigned char* result, size_t n, int iMode = ECB);
void AES_Decrypt(unsigned char* in, unsigned char* result, size_t n, bool bChaining = false, int iMode = ECB);
