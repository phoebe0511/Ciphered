#include <Windows.h>
#include <stdio.h>
#include "AES_Crypt.h"

void _printHex(unsigned char* bBuffer, int iSize)
{
	int i;
	for(i=0;i<iSize;i++)
	{
		printf("%02x ",bBuffer[i]);
		if ( (i+1)%16  ==0)
		{
			printf("\n");
		}
	}
	if ( (i+1)%16  !=0)
	{
		printf("\n");
	}
}

int g_keyBitLen = 128;
int g_TextByteLen = 128;
unsigned char test_key[16] = {0x00  ,0x01  ,0x02  ,0x03  ,0x04  ,0x05  ,0x06  ,0x07  ,0x08  ,0x09  ,0x0a  ,0x0b  ,0x0c  ,0x0d  ,0x0e  ,0x0f};
unsigned char test_text[18]= {0x00  ,0x11  ,0x22  ,0x33  ,0x44  ,0x55  ,0x66  ,0x77  ,0x88  ,0x99  ,0xaa  ,0xbb  ,0xcc  ,0xdd  ,0xee  ,0xff,
                                                             0x00, 0x11};
void main()
{
	unsigned char temp_src[8192];
	unsigned char temp_encryptbuffer[8192];
	unsigned char temp_decryptbuffer[8192];
	unsigned int uiBlockSize = g_keyBitLen/8;
	unsigned int uiTextFinalSize;
	
	AES_setkey(test_key,g_keyBitLen);

	g_TextByteLen = sizeof(test_text) * sizeof(char);
	uiTextFinalSize =(( g_TextByteLen-1)/uiBlockSize + 1) * uiBlockSize;	
	memcpy(temp_src,test_text,g_TextByteLen);
	memset( &(temp_src[g_TextByteLen]),0x00,uiTextFinalSize- g_TextByteLen);
	
	AES_encrypt(temp_encryptbuffer,temp_src,uiTextFinalSize);
	printf("encrypt source:\n");
	_printHex(temp_src,uiTextFinalSize);
	printf("encrypt result:\n");
	_printHex(temp_encryptbuffer,uiTextFinalSize);
	
	
	printf("\nTest decrypt \n");
	AES_decrypt(temp_decryptbuffer,temp_encryptbuffer,uiTextFinalSize);
	printf("decrypt source:\n");
	_printHex(temp_encryptbuffer,uiTextFinalSize);
	printf("decrypt result:\n");
	_printHex(temp_decryptbuffer,g_TextByteLen);

	

}