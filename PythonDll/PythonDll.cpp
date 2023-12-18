#define DLLEXPORT extern "C" __declspec(dllexport)

#include <ctime>
#include <time.h>
#include <winsock2.h> // include must before window.h
#include <iphlpapi.h>
#include <windows.h> 
#include <string>
//#include <string.h>
#include <iostream>
#include <cstdio>
#include <fstream>
#include <sstream>
#include "AES.h"
#include "Base64.h"
#include "md5.h"

#include <direct.h>
#include <cstdlib> 

#pragma comment(lib, "iphlpapi.lib")

#pragma warning(disable: 4996) // avoid GetVersionEx to be warned

using namespace std;

string execCmd(const char* cmd)
{
	char buffer[128] = { 0 };
	std::string result;
	FILE* pipe = _popen(cmd, "r");
	if (!pipe) throw std::runtime_error("_popen() failed!");
	while (!feof(pipe))
	{
		if (fgets(buffer, 128, pipe) != NULL)
			result += buffer;
	}
	_pclose(pipe);

	return result;
}

const char g_key[17] = "asdfwetyhjuytrfd";
const char g_iv[17] = "gfdertfghjkuyrtg";//ECB MODE
string EncryptionAES(const string& strSrc) //AES
{
	size_t length = strSrc.length();
	int block_num = length / BLOCK_SIZE + 1;
	//
	char* szDataIn = new char[block_num * BLOCK_SIZE + 1];
	memset(szDataIn, 0x00, block_num * BLOCK_SIZE + 1);
	strcpy_s(szDataIn, strlen(strSrc.c_str()) + 1, strSrc.c_str());

	//PKCS7Padding
	int k = length % BLOCK_SIZE;
	int j = length / BLOCK_SIZE;
	int padding = BLOCK_SIZE - k;
	for (int i = 0; i < padding; i++)
	{
		szDataIn[j * BLOCK_SIZE + k + i] = padding;
	}
	szDataIn[block_num * BLOCK_SIZE] = '\0';

	//hashed key
	char* szDataOut = new char[block_num * BLOCK_SIZE + 1];
	memset(szDataOut, 0, block_num * BLOCK_SIZE + 1);

	//AES encryption
	AES aes;
	aes.MakeKey(g_key, g_iv, 16, 16);
	aes.Encrypt(szDataIn, szDataOut, block_num * BLOCK_SIZE, AES::CBC);
	string str = base64_encode((unsigned char*)szDataOut,
		block_num * BLOCK_SIZE);
	delete[] szDataIn;
	delete[] szDataOut;
	return str;
}
string DecryptionAES(const string& strSrc) //AES
{
	string strData = base64_decode(strSrc);
	size_t length = strData.length();
	//
	char* szDataIn = new char[length + 1];
	memcpy(szDataIn, strData.c_str(), length + 1);
	//
	char* szDataOut = new char[length + 1];
	memcpy(szDataOut, strData.c_str(), length + 1);

	//AES-CBC decryption
	AES aes;
	aes.MakeKey(g_key, g_iv, 16, 16);
	aes.Decrypt(szDataIn, szDataOut, length, AES::CBC);

	//PKCS7Padding
	if (0x00 < szDataOut[length - 1] <= 0x16)
	{
		int tmp = szDataOut[length - 1];
		for (int i = length - 1; i >= length - tmp; i--)
		{
			if (szDataOut[i] != tmp)
			{
				memset(szDataOut, 0, length);
				cout << "Check if License File is Valid！" << endl;
				break;
			}
			else
				szDataOut[i] = 0;
		}
	}
	string strDest(szDataOut);
	delete[] szDataIn;
	delete[] szDataOut;
	return strDest;
}
string FileDigest(const string& file)
{
	//cout << file << endl;
	ifstream in(file);
	string filename;
	string line;
	getline(in, line);   //
	//cout << "line:"<<line << endl;
	/*
	if (in) // 
	{
		while (getline(in, line)) // 
		{
			cout << line << endl;
		}
	}
	else // 
	{
		cout << "no such file" << endl;
	}
	*/

	in.close();
	return line;
}


string chrHardInf()  //
{
	//CPU ID, Mac Address, Two disk serial number
	char hardInf[256] = { 0 };
	char hard[256] = { 'a','b' };

	//CPU ID
	INT32 dwBuf[4];
	std::string strCPUId;
	char buf[32] = { 0 };
	__cpuidex(dwBuf, 1, 1);
	//printf("%08X%08X\n", dwBuf[3], dwBuf[0]);
	memset(buf, 0, 32);
	sprintf_s(buf, 32, "%08X", dwBuf[3]);
	strCPUId += buf;
	memset(buf, 0, 32);
	sprintf_s(buf, 32, "%08X", dwBuf[0]);
	strCPUId += buf;
	//return strCPUId;
	//cout << "input1:" << input1 << endl;  //
	//cout << "input2:" << input2 << endl;  //

	//cout << "CPU ID " << strCPUId << endl;

	/*
	string hd_seiralss, hd_seiralss1, hd_seiralss2;//two hd serial number
	string hd_seiral = execCmd("wmic path win32_physicalmedia get SerialNumber");
	//hd_seiral.erase(0, hd_seiral.find_first_not_of(" "));
	//hd_seiral.erase(hd_seiral.find_last_not_of(" ") + 1);
	hd_seiralss = hd_seiral.substr(hd_seiral.find('\n') + 1, hd_seiral.length());
	hd_seiralss1 = hd_seiralss.substr(0, hd_seiral.find('\n'));
	hd_seiralss1 = hd_seiralss1.substr(0, hd_seiralss1.find(' '));   //First hd serial number
	hd_seiralss2 = hd_seiralss.substr(hd_seiralss.find('\n') + 1, hd_seiralss.find(' ') + 1);  //Second hd serial number
	hd_seiralss2 = hd_seiralss2.substr(0, hd_seiralss2.find(' '));   //

	//cout << "Hard Disk1: " << hd_seiralss1 << std::endl;
	//cout << "Hard Disk2: " << hd_seiralss2 << std::endl;
	*/

	//computer hardware info-----mac address
	PIP_ADAPTER_INFO pIpAdapterInfo = new IP_ADAPTER_INFO();
	unsigned long adapter_size = sizeof(IP_ADAPTER_INFO);
	int ret = GetAdaptersInfo(pIpAdapterInfo, &adapter_size);
	char local_mac[128] = { 0 };
	int char_index = 0;
	int j = 0;

	if (ret == ERROR_BUFFER_OVERFLOW)
	{
		// overflow, use the output size to recreate the handler
		delete pIpAdapterInfo;
		pIpAdapterInfo = (PIP_ADAPTER_INFO)new BYTE[adapter_size];
		ret = GetAdaptersInfo(pIpAdapterInfo, &adapter_size);
	}

	if (ret == ERROR_SUCCESS)
	{
		int card_index = 0;

		// may have many cards, it saved in linklist
		while (pIpAdapterInfo)
		{
			PIP_ADDR_STRING pIpAddr = &(pIpAdapterInfo->IpAddressList);
			while (pIpAddr)
			{
				char local_ip[128] = { 0 };
				strcpy(local_ip, pIpAddr->IpAddress.String);
				//std::cout << "Local IP: " << local_ip << std::endl;

				pIpAddr = pIpAddr->Next;
			}


			for (int i = 0; i < pIpAdapterInfo->AddressLength; i++)
			{
				char temp_str[10] = { 0 };
				sprintf_s(temp_str, "%02X_", pIpAdapterInfo->Address[i]); // X for uppercase, x for lowercase
				strcpy(local_mac + char_index, temp_str);
				char_index += 3;
			}
			local_mac[17] = '\0'; // remove tail '-'

			//std::cout << "Local Mac  " << local_mac << std::endl;

			break;

		}
	}

	if (pIpAdapterInfo)
		delete pIpAdapterInfo;

	//return local_mac;  
	//mac address
	for (int i = 0; i < strlen(local_mac); i++)
	{
		hardInf[i] = local_mac[i];
	}

	//CPU ID
	j = strlen(local_mac);
	hardInf[j] = '_';
	j++;
	for (int i = 0; i < strCPUId.length(); i++)
	{
		hardInf[j] = strCPUId[i];
		j++;
	}
	hardInf[j] = '\0';

	//cout << "hardInf:" << hardInf << endl;
	char hardInf2[256] = {};
	j = 0;
	for (int i = 0; i < strlen(hardInf); i++)
	{
		if (hardInf[i] != '_')
		{
			hardInf2[j] = hardInf[i];
			j++;
		}
	}

	string hardInfStr;
	hardInfStr = hardInf2;

	return hardInfStr;  // Inf;     //return hardware id：Mac + CPU ID + hard Disk1 + hard Disk2

}

extern "C" _declspec(dllexport) char* __stdcall licInf()  //2 parameters function
{
	char licInfYN[256];
	char hardInfChar[10000] = {};
	string hardInfStr,oriString= FileDigest("lic.dat");
	string dateD,yearD, monthD, DayD;
	SYSTEMTIME sys1;
	GetLocalTime(&sys1); //get time
	//printf("%4d/%02d/%02d %02d:%02d:%02d.%03d", 
	//	sys1.wYear, sys1.wMonth, sys1.wDay, sys1.wHour,
	//	sys1.wMinute, sys1.wSecond, sys1.wMilliseconds);  //time
	int dateInt=0,dataNow= sys1.wYear*10000+ sys1.wMonth*100+ sys1.wDay;
	stringstream ss;
	//cout << dataNow << endl;

	if (oriString.length() > 5)    //use AES
	{
		hardInfStr = DecryptionAES(FileDigest("lic.dat"));//execute decryption
		//cout << "hardInfStr:" << hardInfStr << endl;
		int i, j = 0, k;
		if (hardInfStr.substr(hardInfStr.length() - 12, 4) == "####")      //date, set if license date
		{
			
			dateD= hardInfStr.substr(hardInfStr.length()-8, 8);  //end-date string
			hardInfStr = hardInfStr.substr(0, hardInfStr.length() - 12);   //get string without date
			//cout << dateD << endl;
			//cout << hardInfStr << endl;
			ss << dateD;
			ss >> dateInt;
			//cout << dateInt << endl;
			//cout << dataNow << endl;
			if (dateInt !=0 && dateInt >= dataNow)
			{
				;//
			}
			else if (dateInt != 0 && dateInt < dataNow)
			{
				strncpy(licInfYN, "Falseout", 99);
				cout << "Your License is out of date!" << endl;
				return licInfYN;
			}
			else if (dateInt == 0)
			{
				;
			}
		}
		else
		{
			cout << "Perpetual license" << endl;
		}

		for (i = 0; i < hardInfStr.length(); i++)
		{
			if (oriString.length() > 200)
			{
				if (i % 21 == 0)
				{
					hardInfChar[j] = hardInfStr[i];
					j++;
				}
			}
			else
			{
				hardInfChar[j] = hardInfStr[i];
				j++;
			}
			
		}
		hardInfStr = hardInfChar;


		if (hardInfStr == chrHardInf())          
			strncpy(licInfYN, "True", 99);
		else
			strncpy(licInfYN, "False", 99);
	}
	else
	{   
		MD5 md5;
		md5.update(chrHardInf());
		//cout << md5.toString() << endl;
		//cout << oriString << endl;
		if (oriString == md5.toString())
			strncpy(licInfYN, "True", 99);
		else
			strncpy(licInfYN, "False", 99);
	}
	
	//cout <<"hardInfStr:"<< hardInfStr << endl;

	/*
	//
	char buf1[256];
	_getcwd(buf1, sizeof(buf1));
	printf("%s\n", buf1);
    */
	

	//cout << "licInfYN:" << licInfYN << endl;
	return licInfYN;  // Inf;     //Mac + CPU ID + hard Disk1 + hard Disk2

}
