#ifndef _AESCRYPT_H_
#define _AESCRYPT_H_

#ifdef __cplusplus
extern "C" {
#endif

int AES_setkey(const unsigned char inKey[] , int nKeyBitSize);

/*Encrypt src buffer to AES-encrypt block. size must be times of block size*/
/*EnCryptDest is allocated by caller,*/
int AES_encrypt(unsigned char EnCryptDest[], const unsigned char EnCryptSrc[], unsigned int iSrcByteSize);

/*DeCryptSrc AES-encrypt buffer to AES-decrypt block. size must be times of block size*/
/*DeCrypyDest is allocated by caller,*/
int AES_decrypt(unsigned char DeCrypyDest[], const unsigned char DeCryptSrc[], unsigned int iSrcByteSize);


#ifdef __cplusplus
}
#endif

#endif


