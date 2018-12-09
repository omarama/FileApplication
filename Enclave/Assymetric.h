#pragma once
#include "sgx_trts.h"
#include "sgx_tcrypto.h"
#include <vector>
#include <string>

/*
	The assymetric class is used to sign data with the private key. Furthermore it is used to 
	decrypt data if somebody sends you data encrypted with your public key.
*/
class Assymetric
{
private:
	sgx_ec256_private_t priv = { 0 };
	sgx_ec256_public_t pub = { 0 };
	sgx_ecc_state_handle_t ecc_handle;
public:
	Assymetric();
	~Assymetric();
	void setKeyPair();
	void setKeyPair(const sgx_ec256_private_t &priv, const sgx_ec256_public_t &pub);
	/*Warum hier kein const hinter die Funktion? Warum wird sgx_sign nciht mit vconst priv verwendet?*/
	sgx_status_t sign(const std::vector<uint8_t> &input, sgx_ec256_signature_t &signature);
	bool verify(const std::vector<uint8_t> &input, sgx_ec256_signature_t &signature)const;
	void getPublic(sgx_ec256_public_t &pubKey)const ;
	void getPubPriv(uint8_t keyPair[SGX_ECP256_KEY_SIZE*3])const ;
	void getPriv(sgx_ec256_private_t &privKey)const;
};
