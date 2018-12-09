#include "Assymetric.h"

Assymetric::Assymetric(void)
{
	sgx_ecc256_open_context(&this->ecc_handle);
}
Assymetric::~Assymetric()
{
	sgx_ecc256_close_context(this->ecc_handle);
}
void Assymetric::getPriv(sgx_ec256_private_t &privKey)const
{
	memcpy(privKey.r, this->priv.r, SGX_ECP256_KEY_SIZE);
}
void Assymetric::setKeyPair()
{
	sgx_ecc256_create_key_pair(&this->priv, &this->pub, this->ecc_handle);
}
void Assymetric::setKeyPair(const sgx_ec256_private_t &priv, const sgx_ec256_public_t &pub)
{
	int val = 0; 
	sgx_ecc256_check_point(&pub, ecc_handle, &val);

	if (val)
	{
		memcpy(this->priv.r, priv.r, SGX_ECP256_KEY_SIZE);
		memcpy(this->pub.gx, pub.gx, SGX_ECP256_KEY_SIZE);
		memcpy(this->pub.gy, pub.gy , SGX_ECP256_KEY_SIZE);
		return; 
	}
	else
	{
		return;
	}

}
sgx_status_t Assymetric::sign(const std::vector<uint8_t> &input, sgx_ec256_signature_t &signature) 
{
	sgx_status_t res = SGX_SUCCESS;
	uint8_t result[1];
	res = sgx_ecdsa_sign(input.data(), input.size(), &this->priv, &signature, this->ecc_handle);
	return res;
}
bool Assymetric::verify(const std::vector<uint8_t> &input, sgx_ec256_signature_t &signature) const 
{
	sgx_status_t res = SGX_SUCCESS;
	uint8_t result[1] = { 0 };
	res = sgx_ecdsa_verify(input.data(), input.size(), &this->pub, &signature, result, this->ecc_handle);
	if (result[0] == SGX_EC_VALID)
	{
		return true;
	}
	else if (result[0] == SGX_EC_INVALID_SIGNATURE)
	{
		return false;
	}
	else
	{
		return false;
	}
}
/*Prüfen ob diese Funktionen gebraucht werden */
void Assymetric::getPublic(sgx_ec256_public_t &pubKey)const 
{
	memcpy(&pubKey, &this->pub, SGX_ECP256_KEY_SIZE*2);
}
void Assymetric::getPubPriv(uint8_t keyPair[SGX_ECP256_KEY_SIZE * 3])const 
{
	memcpy(keyPair, &this->priv, SGX_ECP256_KEY_SIZE);
	memcpy(keyPair, &this->pub, SGX_ECP256_KEY_SIZE*2);
}