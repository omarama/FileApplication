#pragma comment(lib, "Ws2_32.lib")
#pragma once
#include <winsock2.h>
#include <windows.h>
#include <winsock.h>
#include <iostream>
#include <vector>
class Ethernet
{
private:
	const int myPort = 9090;
	const std::string myServer = "127.0.0.1";
	SOCKET mySock;
	bool sockInitialized = 0;
	Ethernet();
	~Ethernet();
public:
	// singleton
	static Ethernet& getInstance();
	int initializeSocket();
	int closeSocket();
	int sendOut(const std::string &buf);
	int receiveIn(std::string &buf, int length);
	/*Getter*/
	bool getSockInitialzied() { return this->sockInitialized; }


};