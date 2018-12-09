#include "Sealing.h"
#include "Enclave_t.h"
//#include "Enclave.h"

namespace seal
{
	/*	Description: The sealing function is used to seal a file. This means the input will be encrypted
	with an symmetric key which is only known by the enclave. Only the enclave can generate the key.
	The input will be saved at the passed path.
	Input:
	const std::vector<uint8_t> &in		=	Input vector variable
	const std::string &path				=	Passed saved path
	Output:
	none
	*/
	sgx_status_t sealingBlock(const std::vector<uint8_t> &in, const std::string &path)
	{
		return sealingBlock(in.data(), in.size(), path);
	}
	sgx_status_t sealingBlock(const uint8_t *in,const size_t lengthIn, const std::string &path)
	{
		sgx_status_t res = SGX_SUCCESS;
		uint32_t ciph_size = sgx_calc_sealed_data_size(0, lengthIn);
		if (sgx_is_within_enclave(in, lengthIn))								//Is the address within the prm?
		{
			std::vector <char>sealed(ciph_size);
			/*Seal the data*/
			res = sgx_seal_data(0, NULL, lengthIn, in, ciph_size, (sgx_sealed_data_t*)( sealed.data() ) );
			if (res == SGX_SUCCESS)
			{
				/*Write sealed data to the untrusted part*/
				ocall_write_binary(sealed.data(), ciph_size, path.c_str(), path.size());
			}
		}
		else
		{
			return res;				//Error meldungen noch einfügen 
		}
		return res;
	}
	sgx_status_t unsealingBlock(const std::string &fileName, std::vector<std::uint8_t> &unsealed)
	{
		sgx_status_t res = SGX_SUCCESS;
		int ciph_size = 0;
		std::string pathToFile = "../";
		for (int i = 0; i < fileName.size(); i++)
		{
			pathToFile.push_back(fileName[i]);
		}
		/*take the File size of the sealed data*/
		ocall_get_binary_file_size(pathToFile.c_str(), pathToFile.size(), &ciph_size);
		if (ciph_size > 0)
		{
			std::vector <char> sealed(ciph_size);
			/*Take the file from untrusted*/
			ocall_get_binary(sealed.data(), ciph_size, fileName.c_str(), fileName.size());
			/*Check ich data within trusted environment*/
			if (sgx_is_within_enclave(sealed.data(), ciph_size))
			{
				/*Take the plain size*/
				uint32_t plain_size = sgx_get_encrypt_txt_len((sgx_sealed_data_t*)(sealed.data()));
				unsealed.resize(plain_size);
				if (sgx_is_within_enclave(unsealed.data(), plain_size))
				{
					/*Unseal the data*/
					res = sgx_unseal_data((sgx_sealed_data_t *)(sealed.data()), NULL, NULL, unsealed.data(), &plain_size);
				}
				else
				{
					return SGX_ERROR_BUSY;				//Fehlermeldungen müssen noch angepasst werden.
				}
			}
			else
			{
				return SGX_ERROR_BUSY;
			}
		}
		else
			res = SGX_ERROR_ENCLAVE_FILE_ACCESS;
		return res;

	}
	/*	Description: The unsealing function is used to unseal a file. This means the input will be decrypted
	with an symmetric key which is only known by the enclave. Only the enclave can generate the key.
	The output will be stored in the unsealed vector variable.
	Input:
	const std::string &path					=	Where is the file
	std::vector<std::uint8_t> &unsealed		=	decrypted output variable
	Output:
	none
	*/
}
