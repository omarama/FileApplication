#include "Encryption_Decryption.h"
/*
Description:
Encryption Block. All necessary pre-work for the encryption and the encryption process itself will be executed here
*/
bool encryptionBlock(const uint8_t *plain, const int &lengthPlain, uint8_t *cipher,const int &lengthCipher, const Key &group_key)
{
	sgx_status_t ret;
	/*Is there enough space*/
	if (lengthCipher < (lengthPlain + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE))
	{
		ret = SGX_ERROR_BUSY;
		return ret;
	}
	/*Create the encryption object*/
	Crypt crypt(group_key);	
	/*Encryption struct*/
	EncryptedText encrypted;
	/*Fill the encryption struct*/
	encrypted.length_plain = lengthPlain;
	/*Set Pointer for the encryption */
	encrypted.ivPointer = reinterpret_cast<uint8_t*>(cipher);
	encrypted.cipher = reinterpret_cast<uint8_t*>(cipher + SGX_AESGCM_IV_SIZE);
	encrypted.macPointer = (sgx_aes_gcm_128bit_tag_t*)(cipher + SGX_AESGCM_IV_SIZE + encrypted.length_plain);		
	/*Encrypt the Plaintext*/
	ret = crypt.secureEncrypt(plain, encrypted);	
	/*Was the encryption successfull*/
	if (ret == SGX_SUCCESS)
	{
		return true; 
	}
	else
	{
		return false; 
	}
}
/*
Description:
Decryption Block. All necessary pre-work for the decryption and the decryption process itself will be executed here
*/
bool decryptionBlock(const uint8_t *cipher, const int &lengthCipher, uint8_t *plain, const int &lengthPlain, const Key &group_key)
{
	sgx_status_t ret = SGX_SUCCESS;
	/*Are the values correct*/
	if (lengthCipher < (lengthPlain+SGX_AESGCM_IV_SIZE+SGX_AESGCM_MAC_SIZE))
	{
		ret = SGX_ERROR_BUSY;
		return ret;
	}
	/*Cryption object with the Key and the decrpyption function*/
	Crypt crypt(group_key);								
	/*Decryption Struct*/
	DecryptedText decrypted;
	/*Set pointer for the decryption */
	decrypted.plain = reinterpret_cast<uint8_t*>(plain);
	decrypted.length_plain = lengthCipher - SGX_AESGCM_IV_SIZE - SGX_AESGCM_MAC_SIZE;
	decrypted.ivPointer = cipher;
	decrypted.macPointer = (sgx_aes_gcm_128bit_tag_t*)(cipher + SGX_AESGCM_IV_SIZE + decrypted.length_plain);
	/*Decrypt the Cipher*/
	ret = crypt.secureDecrypt(cipher, decrypted);										
	if (ret == SGX_SUCCESS)
	{
		return true;
	}
	else
	{
		return false;
	}
}
/*
	Set symmetric key for any encryption / decryption purpose.
*/
Crypt::Crypt(const sgx_aes_gcm_128bit_key_t &aesKey)
{
	memcpy(this->groupAesKey, aesKey, sizeof(this->groupAesKey));
}
/*Constructor for the Crypt object*/
Crypt::Crypt()
{
	sgx_aes_gcm_128bit_key_t aesKey;
	memset(aesKey, 0, 16);
	memcpy(this->groupAesKey, aesKey, sizeof(this->groupAesKey));
}
/*Set the cipher key*/
void Crypt::setKey(const sgx_aes_gcm_128bit_key_t &aesKey)
{
	memcpy(this->groupAesKey, aesKey, sizeof(this->groupAesKey));
}
/*
Description:
Decryption function. all necessary data must be provided. Just the IV will be created here
*/
sgx_status_t Crypt::secureEncrypt(const uint8_t *plain, EncryptedText &encrypted) const
{
	sgx_status_t ret = SGX_SUCCESS;			
	/*Create unique ID*/
	sgx_read_rand(encrypted.ivPointer, SGX_AESGCM_IV_SIZE);												
	/*SGX SDK encryption*/
	ret = sgx_rijndael128GCM_encrypt(&this->groupAesKey, plain, encrypted.length_plain, encrypted.cipher, encrypted.ivPointer, SGX_AESGCM_IV_SIZE, nullptr, 0, encrypted.macPointer);			
	return ret;
}
/*
Description:
Encryption function. all necessary data must be provided. Just the IV will be created here
*/
sgx_status_t Crypt::secureDecrypt(const uint8_t *cipher, DecryptedText &decrypted) const
{
	sgx_status_t ret = SGX_SUCCESS;
	/*Decrypt the cipher*/
	ret = sgx_rijndael128GCM_decrypt(&this->groupAesKey, cipher + SGX_AESGCM_IV_SIZE, decrypted.length_plain, decrypted.plain, decrypted.ivPointer, SGX_AESGCM_IV_SIZE, nullptr, 0, decrypted.macPointer);			
	return ret;
}