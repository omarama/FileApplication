#include "Enclave.h"
#include "Enclave_t.h"  /* print_string */
/*Global TDK*/
Key TDK;

/*Struct for the decision of the current encryption/decryption process, if the cipher/plaintext will be returned*/
struct ManagementUnit
{
	bool encryption_decryption = false;						//is the encryption/decryption process successfull?
	bool logging = false;									//is the logging process successfull?
	bool policy = false;									//is the policy check process successfull?
	bool twoFactor = false; 
	bool tdk = false;
};
void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
}
/*ECALL function for the encryption process.
Input is the *plain Pointer. From this address length-bytes will be encrypted stored in the 
*cipher address space. 
*/
sgx_status_t ecall_AuditLoggingEnc_sample(const char *plain, int length, char *cipher, int lengthoutput, const char* filename, int lengthFilename)
{
	sgx_status_t res  = SGX_SUCCESS;															//Error messages
	ManagementUnit manage;																		//managment unit	
	int keyReceived = 0;
	/*Check that the plain and cipher is outside*/
	if ((!sgx_is_outside_enclave(plain, length))|| (!sgx_is_outside_enclave(cipher, lengthoutput)))
	{
		return SGX_ERROR_FILE_BAD_STATUS;
	}

	/*Trusted Setup*/
	if (!memcmp(TDK, calloc(16, 1), 16))
	{
		std::string pathID = "../sealedKey.txt";
		int size = 0; 
		ocall_get_binary_file_size(pathID.c_str(),pathID.size(), &size);
		if (size < 0)
		{
			/*Trusted Setup Create Keypair*/
			Assymetric myID;
			myID.setKeyPair();
			sgx_ec256_public_t pub;
			sgx_ec256_private_t priv;
			myID.getPublic(pub);
			myID.getPriv(priv);
			std::string publicID = "publicID.txt";
			char temp[64];
			for (int i = 0; i < 32; i++)
			{
				temp[i] = pub.gx[31 - i];
				temp[i + 32] = pub.gy[31 - i];
			}
			ocall_write_binary(temp, 64, publicID.c_str(), publicID.size());
			std::vector<uint8_t> sealedKey(priv.r, priv.r + 32);
			sealedKey.insert(sealedKey.end(), pub.gx, pub.gy + 32);
			seal::sealingBlock(sealedKey, "sealedKey.txt");
			return SGX_ERROR_ECALL_NOT_ALLOWED;
		}

	}
	/*Get symmetric key from Trusted Server TDK distribution */
	if (!memcmp(TDK, calloc(16, 1), 16))
	{
		manage.tdk = tDKBlock(TDK);
	}
	else
	{
		manage.tdk = true; 
	}
	/*Policy*/
	//Dummy implementation 
	manage.policy = true; 

	/*Logging Sequence*/
	std::string myfilename(filename, lengthFilename);
	manage.logging=LoggingClient(length, Action::WRITE, reinterpret_cast<const uint8_t> (plain), myfilename);
		
	/*All checks are fine?*/
	if (manage.logging && manage.policy && manage.tdk)
	{
		/*Encryption Sequence*/
		_mm_lfence();
		manage.encryption_decryption = encryptionBlock(reinterpret_cast<const uint8_t*>(plain), length, reinterpret_cast<uint8_t*> (cipher),lengthoutput,TDK);
	}
	if (manage.encryption_decryption)
	{
		return res;
	}
	else
	{
		return SGX_ERROR_BUSY;
	}
}
/*ECALL function for the decryption process.
*/
sgx_status_t ecall_AuditLoggingDec_sample(char *cipher, int lengthCipher, char *plain, int lengthPlain, const char* filename, int lengthFilename)
{
	sgx_status_t res = SGX_SUCCESS;															//Error messages
	ManagementUnit manage;																			//managment unit	
	int keyReceived = 0;
	Assymetric myID;
	/*Check that the plain and cipher is outside*/
	if ((!sgx_is_outside_enclave(cipher, lengthCipher)) || (!sgx_is_outside_enclave(plain, lengthPlain))|| (lengthCipher<=0) || (lengthPlain <=0))
	{
		return SGX_ERROR_FILE_BAD_STATUS;
	}

	/*Get symmetric key from Trusted Server TDK distribution */
	if (!memcmp(TDK, calloc(16, 1), 16))
	{
		manage.tdk = tDKBlock(TDK);
	}
	else
	{
		manage.tdk = true;
	}
	/*Policy*/
	//Dummy implementation 
	manage.policy = true;

	/*Logging Sequence*/
	std::string myfilename(filename, lengthFilename);
	manage.logging = LoggingClient(lengthPlain, Action::READ, reinterpret_cast<const uint8_t> (cipher), myfilename);

	/*decryption sequence*/
	if (manage.logging && manage.policy && manage.tdk)										//open decryption block
	{
		/*Decryption*/
		_mm_lfence();
		manage.encryption_decryption = decryptionBlock(reinterpret_cast<uint8_t*>(cipher), lengthCipher, reinterpret_cast<uint8_t*>(plain), lengthPlain, TDK);
	}
	if (manage.encryption_decryption)
	{
		return res;
	}
	else
	{
		return SGX_ERROR_BUSY;
	}

}