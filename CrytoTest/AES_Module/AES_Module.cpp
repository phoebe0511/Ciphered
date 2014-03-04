// AES_Module.cpp : 定義主控台應用程式的進入點。
//

#include "stdafx.h"
#include "AES_Algorithm.h"


int _tmain(int argc, _TCHAR* argv[])
{
	int i;

	// The array temp stores the key.
	// The array temp1 stores the plaintext.
	unsigned char Key[16] = {0x00  ,0x01  ,0x02  ,0x03  ,0x04  ,0x05  ,0x06  ,0x07  ,0x08  ,0x09  ,0x0a  ,0x0b  ,0x0c  ,0x0d  ,0x0e  ,0x0f};
	unsigned char temp1[16]= {0x00  ,0x11  ,0x22  ,0x33  ,0x44  ,0x55  ,0x66  ,0x77  ,0x88  ,0x99  ,0xaa  ,0xbb  ,0xcc  ,0xdd  ,0xee  ,0xff};
	unsigned char temp2[32]= {0x00  ,0x11  ,0x22  ,0x33  ,0x44  ,0x55  ,0x66  ,0x77  ,0x88  ,0x99  ,0xaa  ,0xbb  ,0xcc  ,0xdd  ,0xee  ,0xff,
							  0x00  ,0x11  ,0x22  ,0x33  ,0x44  ,0x55  ,0x66  ,0x77  ,0x88  ,0x99  ,0xaa  ,0xbb  ,0xcc  ,0xdd  ,0xee  ,0xff};
	unsigned char temp3[32];
	
	// The KeyExpansion routine must be called before encryption.
	AES_SetKey(Key);
	AES_SetIV(Key);

	// The next function call encrypts the PlainText with the Key using AES algorithm.
	AES_Encrypt(temp1, 16, temp1, 16);

	// Output the encrypted text.
	printf("\nText after encryption:\n");
	for (i = 0; i < sizeof(temp1); i++)
	{
		printf("%02x ", temp1[i]);
	}
	printf("\n\n");

	AES_Decrypt(temp1, temp1, 16);
	// Output the decrypted text.
	printf("\nText after decryption:\n");
	for (i = 0; i < sizeof(temp1); i++)
	{
		printf("%02x ", temp1[i]);
	}
	printf("\n\n");


	AES_Encrypt(temp2, 32, temp2, 32, CBC);
	printf("\nText after encryption:\n");
	for (i = 0; i < sizeof(temp2); i++)
	{
		printf("%02x ", temp2[i]);
	}
	printf("\n\n");


	AES_Decrypt(temp2, temp2, 32, CBC);
	printf("\nText after decryption:\n");
	for (i = 0; i < sizeof(temp2); i++)
	{
		printf("%02x ", temp2[i]);
	}
	printf("\n\n");



	AES_Encrypt(temp2, 16, temp3, 32, false, CFB);
	AES_Encrypt(temp2 + 16, 16, temp3 + 16, 16, true, CFB);
	printf("\nText after encryption:\n");
	for (i = 0; i < sizeof(temp3); i++)
	{
		printf("%02x ", temp3[i]);
	}
	printf("\n\n");


	AES_Decrypt(temp3, temp3, 32, false, CFB);
	printf("\nText after decryption:\n");
	for (i = 0; i < sizeof(temp2); i++)
	{
		printf("%02x ", temp2[i]);
	}
	printf("\n\n");




	AES_Encrypt(temp2, 24, temp3, 32, false, CFB);
	printf("\nText after encryption:\n");
	for (i = 0; i < sizeof(temp3); i++)
	{
		printf("%02x ", temp3[i]);
	}
	printf("\n\n");


	AES_Decrypt(temp3, temp2, 32, false, CFB);
	printf("\nText after decryption:\n");
	for (i = 0; i < sizeof(temp2); i++)
	{
		printf("%02x ", temp2[i]);
	}
	printf("\n\n");

	return 0;
}

