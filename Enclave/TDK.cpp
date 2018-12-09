#include "TDK.h"

bool tDKBlock(Key &TDK)//, Channel tsChan)
{
	int ret = 0;
	std::vector <uint8_t> key;
	std::string requestKey = "K";
	/*Establish Secure Channel*/
	Assymetric myID;
	auto& tsChan = Channel::getInstance(&myID);
	ret = tsChan.sendSecure(requestKey);
	if (ret == 1)
	{
		ret = 0;
		key.resize(16);
		if (sgx_is_within_enclave(&key, 16))
		{
			ret = tsChan.receiveSecure(key, 16);
			for (int i = 0; i < 16; i++)
			{
				TDK[i] = key.at(i);
			}
			return true;
		}
		else
		{
			return false;
		}
	}
	else
	{
		return false;
	}
}




