#ifndef _APP_H_
#define _APP_H_
#pragma once
#include "Ethernet.h"
#include <fstream>
#include <vector>
#include <string>
#include <iostream>
#include <chrono>
#include <ctime>
#include "Encryption_untrusted.h"
#include "sgx_urts.h"
#include "sgx_uae_service.h"
#include "sgx_error.h"       /* sgx_status_t */
#include "sgx_eid.h"     /* sgx_enclave_id_t */
#include "Enclave_u.h"
#include "sgx_ukey_exchange.h"
#ifndef TRUE
# define TRUE 1
#endif
#ifndef FALSE
# define FALSE 0
#endif
#if defined(_MSC_VER)
# define TOKEN_FILENAME   "Enclave.token"
# define ENCLAVE_FILENAME "Enclave.signed.dll"
#elif defined(__GNUC__)
# define TOKEN_FILENAME   "enclave.token"
# define ENCLAVE_FILENAME "enclave.signed.so"
#endif

extern sgx_enclave_id_t global_eid;    /* global enclave id */
bool readTxtFile(std::vector < char> &fileText, int &length, const std::string &fileName);
bool writeTxtFile(const char *fileText, int length, const std::string &fileName);
#endif 

