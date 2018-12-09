#include "Channel.h"
/*Create a secure channel DH establishment*/
Channel::Channel(Assymetric *ID) : myAssyId(ID)
{
	/*Unseal the authentication ID*/
	std::vector<uint8_t> unseal;
	seal::unsealingBlock("sealedKey.txt", unseal);
	sgx_ec256_private_t priv;
	sgx_ec256_public_t pub;
	memcpy(priv.r, unseal.data(), 32);
	memcpy(pub.gx, unseal.data() + 32, 32);
	memcpy(pub.gy, unseal.data() + 64, 32);
	/*Set ID object*/
	myAssyId->setKeyPair(priv, pub);
	sgx_ecc256_open_context(&eccHandle);
	/*Generate channel key*/
	this->generateTempSecret();
}
/*return a singleton */
Channel& Channel::getInstance(Assymetric *ID)
{
	static Channel instance(ID);
	return instance; 
}
int Channel::generateTempSecret() 
{
	/*Declaration*/
	int ret = 0; 
	sgx_status_t res = SGX_SUCCESS;
	uint8_t receiveBuffer[64] = { 0 };
	std::vector<uint8_t> packet;
	uint8_t clientRand[32] = { 0 };
	uint8_t serverRand[32] = { 0 };
	sgx_ec256_public_t publicKeyServer;
	sgx_ec256_private_t privateKeyClient;
	sgx_ec256_public_t publicKeyClient;
	sgx_ec256_dh_shared_t myTempSecret;

	/*1. Client random number with signature*/
	sendRandom(clientRand, 32);
	/*2. Server random number*/
	receiveRandom(serverRand, 32);
	/*3. Client public key*/
	sendTempPublicKey(publicKeyClient, privateKeyClient);
	/*4. Server public key */
	receiveServerTempPub(publicKeyServer);
	/*Check if the EC Point from the server is valid!*/
	res = sgx_ecc256_compute_shared_dhkey(&privateKeyClient, &publicKeyServer, &myTempSecret, this->eccHandle);
	if (res == SGX_SUCCESS)
	{
		sgx_sha256_hash_t secret;
		uint8_t premaster[96] = { 0 };
		/*	Fill the premaster secret and generate a random symmetric key based on 
		*	the dh parameter and the random numbers from the server and client 
		*/
		for (int i = 31, j =0; i >= 0; i--,j++)
		{
			premaster[j]=myTempSecret.s[i];
		}
		/*Add the client Rand*/
		memcpy(premaster+32, clientRand, 32);
		/*Add the server rand*/
		memcpy(premaster+64, serverRand, 32);
		/*Calculate master secret*/
		sgx_sha256_msg(premaster, 96, &secret);

		sgx_aes_gcm_128bit_key_t mySymmetricChannelKey;
		memcpy(mySymmetricChannelKey, secret, sizeof(mySymmetricChannelKey));
		this->setKey(mySymmetricChannelKey);
		/*Hello Message Exchange*/
		sendSecure("HelloServer");
		std::string buf; 
		receiveSecure(buf, 11);
		/*Successfull?*/
		if ((buf.substr(0, 11) == "HelloClient"))
		{
			return 1; 
		}
		else
		{
			return -1;
		}
	}
	else
	{
		return 0;
	}
	return 0; 
}
/*	Generate random number and sign it and send it to the server 
*	Finished
*/
int Channel::receiveServerTempPub(sgx_ec256_public_t &serverTempPub)
{
	sgx_status_t res = SGX_SUCCESS;
	/*EC Handle for ECDH*/
	int val = 0;
	int receivedNumber = 0;
	const int MessageSize = 128;
	char receiveBuffer[MessageSize];
	uint8_t validSignature = 0;
	uint8_t signature[64];

	ocall_receive_from_socket(&receivedNumber, receiveBuffer, MessageSize);
	if (receivedNumber == MessageSize)
	{
		//Check the signature
		for (int i = 0; i < 32; i++)
		{
			memcpy(&signature[i], &receiveBuffer[95 - i], 1);
			memcpy(&signature[i + 32], &receiveBuffer[127 - i], 1);
		}
		res = sgx_ecdsa_verify(reinterpret_cast<uint8_t*>(&receiveBuffer[0]), 64, &publicEccTs, (sgx_ec256_signature_t*)&signature, &validSignature, this->eccHandle);
		if (res == SGX_SUCCESS && validSignature == SGX_EC_VALID)
		{
			for (int i = 0; i < 32; i++)
			{
				memcpy(&serverTempPub.gx[i], &receiveBuffer[i], 1);
			}
			for (int i = 0; i < 32; i++)
			{
				memcpy(&serverTempPub.gy[i], &receiveBuffer[32 + i], 1);
			}
			//Check if the received X and Y Parameter are valid EC points
			res = sgx_ecc256_check_point(&serverTempPub, this->eccHandle, &val);
			if (val == 1 && res == SGX_SUCCESS)
			{
				//printf("The tempor public server key is valid!");
				return 1;
			}
			else if (val == 0 && res == SGX_SUCCESS)
			{
				//printf("The temporär public key from the server is not valid!\n");
				return 0;
			}
			else
			{
				//printf("An error is occured during the receiving of the temporär public server key!\n");
				return -1;
			}
		}
		else
		{
			return -1;
		}
	}
	else
		return -1; 
}
int Channel::sendRandom(uint8_t *clientRand, int length)
{
	int ret = 0;
	sgx_status_t res = SGX_SUCCESS;
	std::vector<uint8_t> packet;
	uint8_t signature[64];
	sgx_read_rand(clientRand, length);										//generate client random number
	packet.insert(packet.end(), clientRand, clientRand+length);					//insert random number
	res = myAssyId->sign(packet, (sgx_ec256_signature_t&)signature);
	if (res != SGX_SUCCESS)
	{
		return -1; 
	}
	for (int i = 31; i >= 0; i--)
	{
		packet.push_back(signature[i]);
	}
	for (int i = 63; i >= 32; i--)
	{
		packet.push_back(signature[i]);
	}
	ocall_send_via_socket(&ret, reinterpret_cast<char*>(packet.data()), packet.size());			//send signed packet
	if (ret != packet.size())
	{
		return -1;
	}				
	return ret;
}
/*	Receive random number and check the signature
*/
int Channel::receiveRandom(uint8_t *serverRand, int lenght)
{
	int ret = 0;
	sgx_status_t res = SGX_SUCCESS;
	uint8_t receiveBuffer[96];
	uint8_t valid = 0;
	uint8_t signature[64];

	ocall_receive_from_socket(&ret, reinterpret_cast<char*>(receiveBuffer), 96);
	if (ret == 96)
	{
		for (int i = 0; i < 32; i++)
		{
			memcpy(&signature[i], &receiveBuffer[63-i], 1);
			memcpy(&signature[i+32], &receiveBuffer[95 - i], 1);
		}
		res = sgx_ecdsa_verify(&receiveBuffer[0], 32, &publicEccTs,(sgx_ec256_signature_t*) &signature, &valid, this->eccHandle);
		if (res == SGX_SUCCESS && valid == SGX_EC_VALID)
		{
			memcpy(serverRand, receiveBuffer, 32);
			return 1; 
		}
		else
		{
			return -1; 
		}
	}
	else
		return -1; 
}
/*	Change Endian, sign payload and send to the server
*		Finished
*/
int Channel::sendTempPublicKey(sgx_ec256_public_t &publicKeyClient, sgx_ec256_private_t &privateKeyClient)
{
	/*Declaration*/
	uint8_t signature[64];
	int sentNumber = 0;
	uint8_t packet[SGX_ECP256_KEY_SIZE *2+64];
	/*Initialization*/
	sgx_ecc256_create_key_pair(&privateKeyClient, &publicKeyClient, this->eccHandle);
	/*Change little endian to big endian for the Trusted Server*/
	for (int i = 0; i < 32;i++)
	{
		packet[i] = publicKeyClient.gx[i];
	}
	for (int i = 32; i < 64;i++)
	{
		packet[i] = publicKeyClient.gy[i-32];
	}
	myAssyId->sign(std::vector<uint8_t>(packet, packet + (SGX_ECP256_KEY_SIZE * 2)), (sgx_ec256_signature_t&)signature);									//generate Signature of 1 + public key
	for (int i = 31; i >= 0; i--)
	{
		packet[95-i] = signature[i];
	}
	for (int i = 63; i >= 32; i--)
	{
		packet[159 - i] = signature[i];
	}
	ocall_send_via_socket(&sentNumber, reinterpret_cast<char*> (packet), sizeof(packet));
	if (sentNumber == sizeof(packet)) 
	{
		return 1; 
	}
	else
	{
		return -1;
	}
}
/*	Send payload data encrpyted to the server
*	In Work
*/
int Channel::sendSecure(const std::string &plainDataToSend)
{
	int result = 0; 
	std::vector<uint8_t> payload(plainDataToSend.data(), plainDataToSend.data() + plainDataToSend.size());
	result = sendSecure(payload);
	return result; 
}
int Channel::sendSecure(const std::vector<uint8_t> &payload)
{
	/*Declaration*/
	int sentNumber = 0; 
	std::vector<uint8_t> packetOutput;
	std::string packet;
	EncryptedText cipher;
	packetOutput.resize(12 + 16 + payload.size());
	cipher.ivPointer = packetOutput.data();
	cipher.cipher = packetOutput.data() + 12;
	cipher.macPointer = (sgx_aes_gcm_128bit_tag_t*)&packetOutput.at(12 + payload.size());
	cipher.length_plain = payload.size(); 
	/*Initialization*/
	//this->myTempSecretUsed++;
	//if (this->myTempSecretUsed >= 100)
	//{
	//	generateTempSecret();
	//}
	this->secureEncrypt(payload.data(), cipher);										//encrypt payload
	packet.reserve(12 + SGX_AESGCM_MAC_SIZE + payload.size());
	packet.append(reinterpret_cast<char*>(cipher.ivPointer), 12);
	packet.append(reinterpret_cast<char*>(cipher.cipher), cipher.length_plain);
	packet.append(reinterpret_cast<char*>(cipher.macPointer), SGX_AESGCM_MAC_SIZE);
	/*Send packet to the server*/
	ocall_send_via_socket(&sentNumber, packet.c_str(),packet.size());
	if (sentNumber != packetOutput.size())							
	{
		//printf("An error is occured during the sending socket process!");
		return -1;
	}
	else 
		return (sentNumber - SGX_AESGCM_MAC_SIZE - SGX_AESGCM_IV_SIZE);
}
int Channel::receiveSecure(std::string &plainDataToReceive, const int lengthMessage)
{
	int result = 0;
	std::vector<uint8_t> payload;
	payload.resize(lengthMessage);
	receiveSecure(payload, lengthMessage);
	if (payload.size() == lengthMessage)
	{
		plainDataToReceive.resize(lengthMessage); 
		plainDataToReceive.insert(plainDataToReceive.begin(), payload.data(), payload.data() + payload.size());
		return 1; 
	}
	else
	{
		return -1; 
	}

}
int Channel::receiveSecure(std::vector<uint8_t> &message, const int lengthMessage)
{
	sgx_status_t res = SGX_SUCCESS;
	int ret = 0;
	std::vector <uint8_t> receive;
	receive.resize(lengthMessage + 16 + 12);
	ocall_receive_from_socket(&ret, reinterpret_cast<char*>(receive.data()), lengthMessage + 12 + 16);
	DecryptedText dec;
	dec.ivPointer = receive.data();
	dec.macPointer = (sgx_aes_gcm_128bit_tag_t*)&receive.at(12 + lengthMessage);
	message.resize(lengthMessage);
	dec.plain = message.data();
	dec.length_plain = lengthMessage; 

	res = this->secureDecrypt(receive.data(),dec);
	if (res == SGX_SUCCESS)
	{
		return ret; 
	}
	else
	{
		//printf("There is an error occured during the receiving process!");
		return -1;
	}
}