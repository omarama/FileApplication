#pragma once
#include "Assymetric.h"
#include "Encryption_Decryption.h"
#include "Sealing.h"
#include "Enclave_t.h"

static const sgx_ec256_public_t publicEccTs = {
	{
		0xed, 0x4b, 0x07, 0x7f, 0x7a, 0x62, 0x82, 0xa8, 
		0x07, 0x8e, 0x47, 0xd2, 0xc0, 0x3e, 0xd7, 0x2b, 
		0x1d, 0x90, 0xb2, 0xcf, 0x4d, 0x7a, 0xff, 0xc9,
		0xf0, 0xb7, 0xa1, 0xb9, 0x84, 0x93, 0x92, 0x4a
	},
	{
		0x0f, 0xb9, 0x76, 0x74, 0x2b, 0x74, 0xbb, 0xd2, 
		0x27, 0x0c, 0x3d, 0x53, 0x27, 0x47, 0xd5, 0xa8,
		0xe8, 0xc0, 0xbb, 0xb1, 0x7b, 0xb6, 0xd4, 0xc4,
		0x32, 0x71, 0xe9, 0xc9, 0x70, 0xf1, 0x0c, 0x94
	}
};
enum Packettype
{
	LOG,
	CHANNEL_KEY,
	ADD_CLIENT
};
class Channel : Crypt
{
private:
	//int myTempSecretUsed = 0;
	Assymetric *myAssyId;
	sgx_ecc_state_handle_t eccHandle;
	int receiveServerTempPub(sgx_ec256_public_t &serverTempPub);
	int generateTempSecret();
	int sendTempPublicKey(sgx_ec256_public_t &publicKeyClient, sgx_ec256_private_t &privateKeyClient);
	int sendRandom(uint8_t *clientRand, int length);
	int receiveRandom(uint8_t *serverRand, int lenght);
	Channel::Channel(Assymetric *ID);
public:
	static Channel& getInstance(Assymetric *ID);
	int sendSecure(const std::vector<uint8_t> &message);
	int sendSecure(const std::string &plainDataToSend);
	int receiveSecure(std::vector<uint8_t> &message,const int lengthMessage);
	int receiveSecure(std::string &plainDataToReceive, const int lengthMessage);
};

