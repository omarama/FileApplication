#pragma once
#include "sgx_trts.h"
#include "sgx_tcrypto.h"
#include "sgx_tae_service.h"
#include <string>
#include "Channel.h"
enum class Action
{
	READ,
	WRITE
};

bool LoggingClient(const int &plainSize, Action act, const uint8_t &plaintextPointer, std::string filename);
/*
	The logging Client class generates a logging record, whcich shuld be transfered to the central server.
	Information like the time, document title, etc should be stored. 
	The hashing and signature with the private key will be done within the TLS channel to ensure 
	CIA.
*/
class LoggingRecord
{
private:
	/*all necessary information within the logging Record*/
	const uint8_t* documentPointer;
	long int timeStamp;									//Unix time
	int hostID;								//cpu id 
	std::string fileName;							//file name
	std::string versionNumber;							//file version
	int documentSize;									//file size
	sgx_sha256_hash_t documentHash;
	Action action;									//Read or write access
public:
 	LoggingRecord(const int &documentlength, Action act, const uint8_t &plaintextPointer, std::string filename);
	std::string getLoggingRecord() const;					//create Logging Record
};