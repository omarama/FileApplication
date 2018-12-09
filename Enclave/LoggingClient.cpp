#include "LoggingClient.h"
#include "Enclave_t.h"
#include "Enclave.h"

bool LoggingClient(const int &plainSize, Action act, const uint8_t &plaintextPointer, std::string filename)
{
	int ret=0;				//Sent message size variable
	/*Establish Secure Channel*/
	Assymetric myID;
	auto& tsChan = Channel::getInstance(&myID);
	/*Generate Logging Record*/
	LoggingRecord myLogRecord(plainSize, act ,plaintextPointer,filename);
	std::string message = myLogRecord.getLoggingRecord();
	if (message.size() == 100)
	{
		/*Send Key Letter L to indicate Logging Record will be send. */
		ret = tsChan.sendSecure("L");
		if (ret == 1)
		{
			/*Send Logging Record*/
			ret = tsChan.sendSecure(message);
			/*Calculate expected Response*/
			sgx_sha256_hash_t expectedResponse;
			sgx_sha256_msg(reinterpret_cast<const uint8_t*>(myLogRecord.getLoggingRecord().c_str()), 100, &expectedResponse);
			/*Are the Logging Record fully sent*/
			if (ret == 100)
			{
				std::string response; 
				response.resize(32);
				tsChan.receiveSecure(response, 32);
				/*Check the response*/
				if (!memcmp(response.c_str(), expectedResponse, 32))
				{
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
		
	}
	else
	{
		return false; 
	}
	return false; 
}
LoggingRecord::LoggingRecord(const int &documentlength, Action act,const uint8_t &plaintextPointer, std::string filename) 
	: fileName(filename), hostID(2), versionNumber("0"),documentPointer(&plaintextPointer), documentSize(documentlength), action(act)
{
	ocall_get_timestamp(&this->timeStamp); 
}
/*Logging record structure
	0 - 6						"LOGREC"
	7 -	10						"TIME"
	11 - 20						Unixtime
	21 - 25						"ACTION"
	26 - 26						act
	27 - 28						"ID"
	29 - 38						id
	39 - 42						"SIZE"
	43 - 52						filesize
	53 - 56						"VERS"
	57 - 66						verion
	67 - 70						"NAME"
	71 - 90						name
*/
std::string LoggingRecord::getLoggingRecord() const 
{
	std::string loggingRec(100,' ');
	std::string templ="";
	loggingRec.replace(0, 6, "LOGREC");
	loggingRec.replace(6, 4, "TIME");
	loggingRec.replace(10, std::to_string(this->timeStamp).size(),std::to_string(this->timeStamp));
	loggingRec.replace(21, 6, "ACTION");
	if (this->action == Action::WRITE)
	{
		loggingRec.replace(27,1 ,"1");
	}
	else if (this->action == Action::READ)
	{
		loggingRec.replace(27,1, "0");
	}
	loggingRec.replace(28, 2, "ID");
	loggingRec.replace(30, std::to_string(this->hostID).size(),std::to_string(this->hostID));
	loggingRec.replace(40, 4, "SIZE");
	loggingRec.replace(44, std::to_string(this->documentSize).size(), std::to_string(this->documentSize));
	loggingRec.replace(54, 4, "VERS");
	loggingRec.replace(58,this->versionNumber.size(), this->versionNumber);
	loggingRec.replace(68, 4, "NAME");
	loggingRec.replace(72,this->fileName.size(), this->fileName);
	for (int i = loggingRec.size(); i < 100; i++)
	{
		loggingRec.replace(i, 1, " ");
	}
	return loggingRec;
}
