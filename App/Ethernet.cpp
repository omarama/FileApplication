#include "Ethernet.h"

Ethernet::Ethernet()
{
	int res = 0;
	res = initializeSocket();
	if (res)
	{
		this->sockInitialized = true;
	}
}
Ethernet& Ethernet::getInstance()
{
	static Ethernet instance;
	return instance;
}
int Ethernet::initializeSocket()
{
	WSADATA	wsaData;
	SOCKADDR_IN serverAddr, thisSenderInfo;
	int retCode;
	//std::string data = "Hello from the enclave";
	WORD dllVersion = MAKEWORD(2, 1);
	// Initialize Winsock version 2.2
	WSAStartup(dllVersion, &wsaData);
	WSAStartup(MAKEWORD(2, 2), &wsaData);
	//printf("Client: Winsock DLL status is %s.\n", wsaData.szSystemStatus);

	// Create a new socket to make a client connection.
	// AF_INET = 2, The Internet Protocol version 4 (IPv4) address family, TCP protocol
	this->mySock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (this->mySock == INVALID_SOCKET)
	{
		printf("Client: socket() failed! Error code: %ld\n", WSAGetLastError());
		// Do the clean up
		WSACleanup();
		// Exit with error
		return -1;
	}
	else
	{
		//printf("Client: socket() is OK!\n");
	}
	// IPv4
	serverAddr.sin_family = AF_INET;
	// Port no.
	serverAddr.sin_port = htons(this->myPort);
	// The IP address
	serverAddr.sin_addr.s_addr = inet_addr(this->myServer.c_str());

	// Make a connection to the server with socket this->mySock.
	retCode = connect(this->mySock, (SOCKADDR *)&serverAddr, sizeof(serverAddr));
	if (retCode != 0)
	{
		printf("Client: connect() failed! There is no Server available! Make sure the Trusted Server is running!\n", WSAGetLastError());
		// Close the socket
		closesocket(this->mySock);
		// Do the clean up
		WSACleanup();
		// Exit with error
		return 0;
	}
	else
	{
		printf("Client: connect() is OK, got connected...\n");
		printf("Client: Ready for sending and/or receiving data...\n");
	}
	return 1;
}
int Ethernet::sendOut(const std::string &buf)
{
	int socketResult=0;
	socketResult = send(this->mySock, buf.c_str(), buf.size(), 0);
	if (socketResult == SOCKET_ERROR)
	{
		printf("send failed: %d\n", WSAGetLastError());
		return 0;
	}
	//printf("Bytes send: %d\n" , socketResult);
	return socketResult;
}
int Ethernet::receiveIn(std::string &buf, int length)
{
	char* buffer;
	buffer = new char[length];
	int socketResult = 0;
	socketResult = recv(this->mySock, buffer, length, 0);
	if (socketResult > 0)
	{
		//printf("Bytes received: %d\n", socketResult);
		buf = std::string(buffer, socketResult);
	}
	else if (socketResult == SOCKET_ERROR)
	{
		printf("Received failed : %d\n", WSAGetLastError());
		delete[] buffer;
		return -1;
	}
	delete[] buffer;
	return socketResult;
}
int Ethernet::closeSocket()
{
	if (closesocket(this->mySock) != 0)
	{
		printf("Client: Cannot close \"this->mySocket\" socket. Error code: %ld\n", WSAGetLastError());
		return 0;
	}
	else
	{ 
		printf("Client: Closing \"this->mySocket\" socket...\n");
	}
	// When your application is finished handling the connection, call WSACleanup.
	if (WSACleanup() != 0)
	{
		printf("Client: WSACleanup() failed!...\n");
		return 0;
	}
	else
	{
		printf("Client: WSACleanup() is OK...\n");
		return 1;
	}
}
Ethernet::~Ethernet()
{
	int res = 0;
	res = closeSocket();
	if (res)
	{
		this->sockInitialized = false;
	}
}