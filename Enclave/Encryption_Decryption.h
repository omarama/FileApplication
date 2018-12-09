#pragma once
#include "sgx_trts.h"
#include "sgx_tcrypto.h"
#include <vector>

using Key = sgx_aes_gcm_128bit_key_t;
/*Struct for the decryption process. The whole output data at the decryption is hold here*/
struct DecryptedText
{
	const uint8_t *ivPointer;				//Pointer to the IV 
	uint8_t *plain;							//Pointer to the plaintext
	const sgx_aes_gcm_128bit_tag_t *macPointer;		//Pointer to the mac
	int length_plain;				//holds the plaintext length 
};
/*Struct for the encryption process. The whole output data at the encrpytion is hold here.*/
struct EncryptedText
{
	uint8_t *ivPointer;					//Pointer to the IV
	uint8_t* cipher;					//Pointer to the ciphertext
	sgx_aes_gcm_128bit_tag_t *macPointer;		//Pointer to the mac
	int length_plain;					//holds the plaintext length
};
/*
	Encrypt the &text variable with the group key and output the &encrpyted struct, containing 
	the cihpertext. 
*/
bool encryptionBlock(const uint8_t *plain, const int &lengthPlain, uint8_t *cipher, const int &lengthCipher, const Key &group_key);
/*
	Decrypt the &text variable with the group key and output the &encrpyted struct, containing
	the cihpertext.
*/
bool decryptionBlock(const uint8_t *cipher, const int &lengthCipher, uint8_t *plain, const int &lengthPlain, const Key &group_key);
/*Class for the encryption and decryption process.*/
class Crypt
{
private:
	sgx_aes_gcm_128bit_key_t groupAesKey;								//symmetric group key for the encryption/decryption process
public:
	/*Set symmetric key an initialization*/
	Crypt();
	Crypt(const sgx_aes_gcm_128bit_key_t &aesKey);
	void setKey(const sgx_aes_gcm_128bit_key_t &aesKey);
	sgx_status_t secureEncrypt(const std::uint8_t *plain, EncryptedText &encrypted) const;
	sgx_status_t secureDecrypt(const std::uint8_t *cipher, DecryptedText &decrypted) const;
};