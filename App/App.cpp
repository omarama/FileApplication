#include "App.h"
#ifdef _MSC_VER
# include <Shlobj.h>
#else
# include <unistd.h>
# include <pwd.h>
# define MAX_PATH FILENAME_MAX
#endif
int MAX_SIZE = pow(1024, 1) * 100;
int writeFile(std::string newValue);
/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;
typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;
/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        nullptr
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
		nullptr
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
		nullptr
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
		nullptr
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
		nullptr
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
		nullptr
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
		nullptr
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
		nullptr
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
		nullptr
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
		nullptr
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
		nullptr
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
		nullptr
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
		nullptr
    },
    {
        SGX_ERROR_NDEBUG_ENCLAVE,
        "The enclave is signed as product enclave, and can not be created as debuggable enclave.",
		nullptr
    },
};
/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(nullptr != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }
    
    if (idx == ttl)
    	printf("Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer Reference\" for more details.\n", ret);
}
/* Initialize the enclave:
 *   Step 1: try to retrieve the launch token saved by last transaction
 *   Step 2: call sgx_create_enclave to initialize an enclave instance
 *   Step 3: save the launch token if it is updated
 */
int initialize_enclave(void)
{
    char token_path[MAX_PATH] = {'\0'};
    sgx_launch_token_t token = {0};
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int updated = 0;
    
    /* Step 1: try to retrieve the launch token saved by last transaction 
     *         if there is no token, then create a new one.
     */
#ifdef _MSC_VER
    /* try to get the token saved in CSIDL_LOCAL_APPDATA */
    if (S_OK != SHGetFolderPathA(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, token_path)) {
        strncpy_s(token_path, _countof(token_path), TOKEN_FILENAME, sizeof(TOKEN_FILENAME));
    } else {
        strncat_s(token_path, _countof(token_path), "\\" TOKEN_FILENAME, sizeof(TOKEN_FILENAME)+2);
    }

    /* open the token file */
    HANDLE token_handler = CreateFileA(token_path, GENERIC_READ|GENERIC_WRITE, FILE_SHARE_READ, nullptr, OPEN_ALWAYS, NULL, nullptr);
    if (token_handler == INVALID_HANDLE_VALUE) {
        printf("Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
    } else {
        /* read the token from saved file */
        DWORD read_num = 0;
        ReadFile(token_handler, token, sizeof(sgx_launch_token_t), &read_num, nullptr);
        if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
            /* if token is invalid, clear the buffer */
            memset(&token, 0x0, sizeof(sgx_launch_token_t));
            printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
        }
    }
#else /* __GNUC__ */
    /* try to get the token saved in $HOME */
    const char *home_dir = getpwuid(getuid())->pw_dir;
    
    if (home_dir != nullptr &&
        (strlen(home_dir)+strlen("/")+sizeof(TOKEN_FILENAME)+1) <= MAX_PATH) {
        /* compose the token path */
        strncpy(token_path, home_dir, strlen(home_dir));
        strncat(token_path, "/", strlen("/"));
        strncat(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME)+1);
    } else {
        /* if token path is too long or $HOME is NULL */
        strncpy(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME));
    }

    FILE *fp = fopen(token_path, "rb");
    if (fp == nullptr && (fp = fopen(token_path, "wb")) == nullptr) {
        printf("Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
    }

    if (fp != nullptr) {
        /* read the token from saved file */
        size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
        if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
            /* if token is invalid, clear the buffer */
            memset(&token, 0x0, sizeof(sgx_launch_token_t));
            printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
        }
    }
#endif
    /* Step 2: call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, nullptr);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
#ifdef _MSC_VER
        if (token_handler != INVALID_HANDLE_VALUE)
            CloseHandle(token_handler);
#else
        if (fp != nullptr) fclose(fp);
#endif
        return -1;
    }

    /* Step 3: save the launch token if it is updated */
#ifdef _MSC_VER
    if (updated == FALSE || token_handler == INVALID_HANDLE_VALUE) {
        /* if the token is not updated, or file handler is invalid, do not perform saving */
        if (token_handler != INVALID_HANDLE_VALUE)
            CloseHandle(token_handler);
        return 0;
    }
    
    /* flush the file cache */
    FlushFileBuffers(token_handler);
    /* set access offset to the begin of the file */
    SetFilePointer(token_handler, 0, nullptr, FILE_BEGIN);

    /* write back the token */
    DWORD write_num = 0;
    WriteFile(token_handler, token, sizeof(sgx_launch_token_t), &write_num, nullptr);
    if (write_num != sizeof(sgx_launch_token_t))
        printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
    CloseHandle(token_handler);
#else /* __GNUC__ */
    if (updated == FALSE || fp == nullptr) {
        /* if the token is not updated, or file handler is invalid, do not perform saving */
        if (fp != nullptr) fclose(fp);
        return 0;
    }

    /* reopen the file with write capablity */
    fp = freopen(token_path, "wb", fp);
    if (fp == nullptr) return 0;
    size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
    if (write_num != sizeof(sgx_launch_token_t))
        printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
    fclose(fp);
#endif
    return 0;
}
#if defined(_MSC_VER)
/* query and enable SGX device*/
int query_sgx_status()
{
    sgx_device_status_t sgx_device_status;
    sgx_status_t sgx_ret = sgx_enable_device(&sgx_device_status);
    if (sgx_ret != SGX_SUCCESS) {
        printf("Failed to get SGX device status.\n");
        return -1;
    }
    else {
        switch (sgx_device_status) {
        case SGX_ENABLED:
            return 0;
        case SGX_DISABLED_REBOOT_REQUIRED:
            printf("SGX device has been enabled. Please reboot your machine.\n");
            return -1;
        case SGX_DISABLED_LEGACY_OS:
            printf("SGX device can't be enabled on an OS that doesn't support EFI interface.\n");
            return -1;
        case SGX_DISABLED:
            printf("SGX is not enabled on this platform. More details are unavailable.\n");
            return -1;
        case SGX_DISABLED_SCI_AVAILABLE:
            printf("SGX device can be enabled by a Software Control Interface.\n");
            return -1;
        case SGX_DISABLED_MANUAL_ENABLE:
            printf("SGX device can be enabled manually in the BIOS setup.\n");
            return -1;
        case SGX_DISABLED_HYPERV_ENABLED:
            printf("Detected an unsupported version of Windows* 10 with Hyper-V enabled.\n");
            return -1;
        case SGX_DISABLED_UNSUPPORTED_CPU:
            printf("SGX is not supported by this CPU.\n");
            return -1;
        default:
            printf("Unexpected error.\n");
            return -1;
        }
    }
}
#endif
/* OCall functions */
long int ocall_get_timestamp()
{
	long int ret = 0;
	std::time_t t = std::time(0);
	ret = static_cast<long int>(t);
	return ret;
}
/*Kann noch rausgenommen werden */
void ocall_print_string(const char *str)
{
	printf("%s", str);
}
/*Input Block / Output Block*/
void ocall_get_binary_file_size(const char *path, int pathLength, int *size)
{
	std::fstream motd(path, std::ios::binary | std::ios::in | std::ios::ate);
	if (motd.is_open()) {
		motd.seekg(0, std::ios::beg);
		int begin = motd.tellg();										//first position
		motd.seekg(0, std::ios::end);									//go to std::ios::end position
		int end = motd.tellg();										//last position
		int file_length = end - begin;
		*size = file_length;
	}
	else
	{
		printf("Error during file size!");
		*size = -1;
	}
	return;
}
void ocall_get_binary(char *text, int lengthText, const  char *fileName, int fileNameSize)
{
	std::string path = "../";
	for (int i = 0; i < fileNameSize; i++)
	{
		path.push_back(fileName[i]);
	}
	std::ifstream input(path, std::ios::binary);
	if (input.is_open())
	{
		int begin = input.tellg();										//first position
		input.seekg(0, std::ios::end);									//go to std::ios::end position
		int end = input.tellg();										//last position
		int file_length = end - begin;									//get the file length
		input.seekg(0);													//go back to first position
		if (lengthText <= file_length)
		{
			input.read(text, lengthText);
			input.close();
		}
		else
		{
			input.read(text, file_length);
			input.close();
		}
	}
	else
	{
		printf("Cannot open binary file!\n");
	}
	return;
}
void ocall_write_binary(char *text, int textLength, const char* fileName, int fileNameSize)
{
	std::string path = "../";
	for (int i = 0; i < fileNameSize; i++)
	{
		path.push_back(fileName[i]);
	}
	std::ofstream output(path, std::ios::binary);
	if (output.is_open())
	{
		output.write(text, textLength);
		output.close();
	}
	else
	{
		printf("Cannot write file!\n");
	}
}
/*Communicator Block*/
int ocall_send_via_socket(const char* sendBuf, int length)
{
	auto& sock = Ethernet::getInstance();
	if (sock.getSockInitialzied())
	{
		int ret = 0;
		Sleep(1);
		ret = sock.sendOut(std::string(sendBuf, length));

		return ret;
	}
	else
	{
		return -1;
	}
}
int ocall_receive_from_socket(char* recvBuf, int length)
{
	auto& sock = Ethernet::getInstance();
	int result = 0;
	std::string temp;
	if (sock.getSockInitialzied())
	{
		result = sock.receiveIn(temp, length);
		if (result != -1 && result < length)
		{
			for (int i = 0; i < result; i++)
			{
				recvBuf[i] = temp.at(i);
			}
			printf("Try again");
			Sleep(1000);
			int result2 = sock.receiveIn(temp, length - result);
			for (int i = result, j = 0; i < result2; i++)
			{
				recvBuf[i] = temp.at(j);
				j++;
			}
			return (result + result2);
		}
		else  if (result != -1 && result == length)
		{
			for (int i = 0; i < length; i++)
			{
				recvBuf[i] = temp.at(i);
			}
			return result;
		}
		else {
			printf("Error at the reading process!\n");
			return -1;
		}
	}
	else
	{
		return -1;
	}
}
/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
	(void)(argc);
	(void)(argv);
	sgx_status_t ret = SGX_SUCCESS;
#if defined(_MSC_VER)
	if (query_sgx_status() < 0) {
		/* either SGX is disabled, or a reboot is required to enable SGX */
		printf("Enter a character before exit ...\n");
		getchar();
		return -1;
	}
#endif 
	/*Read File for encryption input*/
	int file_length;
	std::string fileName = "Testfile.txt";
	std::string path = "../" + fileName;
	printf("\nSecure Enclave Application.\n");
	std::vector <char> buf;
	int j = 0; 


	/*Start Time*/
	std::chrono::time_point<std::chrono::system_clock> start, end;
	/* Initialize the enclave */
	start = std::chrono::system_clock::now();
	if (initialize_enclave() < 0) {
		printf("Error. Enter a character before exit ...\n");
		getchar();
		return -1;
	}
	end = std::chrono::system_clock::now();
	int elapsed_seconds = std::chrono::duration_cast<std::chrono::microseconds>
		(end - start).count();
	std::time_t end_time = std::chrono::system_clock::to_time_t(end);
	std::cout << "The initialization process of the Secure Enclave Application took " << elapsed_seconds << " us\n";
	sgx_status_t ecall_ret = SGX_SUCCESS;

	int ciphersize;
	std::vector<char> cipherForDec;
	for (int j = 0; j <1; j++)
	{
		buf.clear();
		file_length = 0;
		std::cout << "How many should be red[Byte]? Maximum is 500 MiB" << std::endl;
		std::cin >> MAX_SIZE;
		std::cout << "OK! " << MAX_SIZE << " kiB will be red!" << std::endl; 
		start = std::chrono::system_clock::now();

		/*Open the File*/
		readTxtFile(buf, file_length, path);

		/*End Time*/
		end = std::chrono::system_clock::now();
		elapsed_seconds = std::chrono::duration_cast<std::chrono::microseconds>
			(end - start).count();
		end_time = std::chrono::system_clock::to_time_t(end);
		std::cout << "The reading process of the file took " << elapsed_seconds << " us\n";
		ciphersize = (file_length + 16 + 12);
		std::vector<char> cipher(ciphersize);

		/*Start the encryption process via the ecall function*/
		for (int i = 0; i < 1; i++)
		{
			std::string perform; 
			start = std::chrono::system_clock::now();
			ret = ecall_AuditLoggingEnc_sample(global_eid, &ecall_ret, buf.data(), buf.size(), cipher.data(), cipher.size(),fileName.c_str(), fileName.size());
			end = std::chrono::system_clock::now();
			if (ecall_ret == SGX_SUCCESS)
			{
				elapsed_seconds = std::chrono::duration_cast<std::chrono::microseconds>
					(end - start).count();
				end_time = std::chrono::system_clock::to_time_t(end);
				perform.append(std::to_string(elapsed_seconds));
				perform.push_back('\n');
				//writeFile(perform);
				std::cout << "The encryption process of the Secure Enclave Application took " << elapsed_seconds << " us\n";
				perform.clear();
				/*Write the file finally*/
				std::vector <char> ciphertext(cipher.data(), cipher.data() + ciphersize);
				writeTxtFile(ciphertext.data(), ciphertext.size(), "cipher.txt");
				/*Just for decryption needed*/
				cipherForDec.reserve(ciphersize);
				cipherForDec.insert(cipherForDec.begin(), cipher.data(), cipher.data() + cipher.size());
			}
			else
			{
				std::cout << "The encryption process failed!" << std::endl;
			}	
			/*Write file to SSD*/

		}
		/*Increase the file Size*/
		if (MAX_SIZE == (pow(1024, 1) * 100))
		{
			MAX_SIZE = pow(1024, 2);
		}
		else if (MAX_SIZE == (pow(1024, 2)))
		{
			MAX_SIZE = pow(1024, 2) * 3;
		}
		else if (MAX_SIZE == (pow(1024, 2) * 3))
		{
			MAX_SIZE = pow(1024, 2) * 5;
		}
		else if (MAX_SIZE == (pow(1024, 2) * 5))
		{
			MAX_SIZE = pow(1024, 2) * 10;
		}
		else if (MAX_SIZE == (pow(1024, 2) * 10))
		{
			MAX_SIZE = pow(1024, 2) * 20;
		}
		else if (MAX_SIZE == (pow(1024, 2) * 20))
		{
			MAX_SIZE = pow(1024, 2) * 40;
		}
		else if (MAX_SIZE == (pow(1024, 2) * 40))
		{
			MAX_SIZE = pow(1024, 2) * 80;
		}
		else if (MAX_SIZE == (pow(1024, 2) * 80))
		{
			MAX_SIZE = pow(1024, 2) * 160;
		}
		else if (MAX_SIZE == (pow(1024, 2) * 160))
		{
			MAX_SIZE = pow(1024, 2) * 320;
		}
		else if (MAX_SIZE == (pow(1024, 2) * 320))
		{
			MAX_SIZE = pow(1024, 2) * 500;
		}
	}

	/*Decryption process*/
	int plainsize = (file_length);
	std::vector<char> plain(plainsize);
	fileName = "Cipher.txt";
	start = std::chrono::system_clock::now();
	for (int i = 0; i < 1; i++)
	{
		ret = ecall_AuditLoggingDec_sample(global_eid, &ecall_ret, cipherForDec.data(), cipherForDec.size(), plain.data(), plain.size(), fileName.c_str(), fileName.size());
	}
	end = std::chrono::system_clock::now();
	if (ecall_ret == SGX_SUCCESS)
	{
		elapsed_seconds = std::chrono::duration_cast<std::chrono::microseconds>
			(end - start).count();
		end_time = std::chrono::system_clock::to_time_t(end);
		std::cout << "The decryption process of the Secure Enclave Application took " << elapsed_seconds << " us for\n";
		std::vector <char> plaintext(plain.data(), plain.data() + plainsize);
		/*Write the file*/
		writeTxtFile(plaintext.data(), plaintext.size(), "plain.txt");
	}
	else
	{
		std::cout << "The decryption process failed!" << std::endl; 
	}
	auto& sock = Ethernet::getInstance();
	if (sock.getSockInitialzied())
	{
		sock.closeSocket();
	}

	/*Dealocate all dynamic memory*/
    sgx_destroy_enclave(global_eid);
    printf("Enter a character before exit ...\n");
	getchar();
	getchar();
    return 0;
}
/*Read a TXT file*/
bool readTxtFile(std::vector < char> &fileText, int &length, const std::string &fileName)
{
	std::ifstream bigFile(fileName.c_str(), std::ifstream::binary);
	fileText.reserve(MAX_SIZE);

	bigFile.seekg(0, bigFile.end);
	length = bigFile.tellg();
	bigFile.seekg(0, bigFile.beg);
	if (length < MAX_SIZE)
	{
		fileText.resize(length);
		bigFile.read(fileText.data(), length);
	}else 
	{
		length = MAX_SIZE;
		fileText.resize(length);
		bigFile.read(fileText.data(), MAX_SIZE);
	}
	if (bigFile.gcount()==length)
	{
		std::cout << "The reading size is " << length/1000 << " kB" << std::endl;
		bigFile.close();
		return true;
	}
	else
	{
		std::cout << "Error: only " << bigFile.gcount() << " could be read";
		bigFile.close();
		return false;
	}
}
/*Write a TXT file*/
bool writeTxtFile(const char *fileText, int length, const std::string &fileName)
{
	std::ofstream bigFile("../" + fileName,std::ios::binary);
	if (bigFile.is_open())
	{
		bigFile.write(fileText, length);
		bigFile.close();
		return true;
	}
	else
	{
		printf("Cannot write file!\n");
		return false;
	}
}
/*Just used for performance Test. This will write the performance rest file to the dedicated file*/
int writeFile(std::string newValue)
{
	std::ofstream bigFile;
	bigFile.open("../SGXPerformance.txt", std::ios::app);
	if (bigFile.is_open())
	{
		bigFile.write(newValue.c_str(), newValue.size());
		bigFile.close();
		return true;
	}
	else
	{
		printf("Cannot write file!\n");
		return false;
	}
}
