#include <fstream>  
#include <string>  
#include <iostream>  
#include <vector>
#include <Windows.h>
#include "dirent.h"
#include <io.h>
#include <stack>

#include "threadpool.h"
#include <stdlib.h>
#include <stdio.h>

using namespace std;


#pragma comment(lib, "WS2_32.lib")
string getIP()
{
	WSADATA WSAData;
	char hostName[256];
	if (!WSAStartup(MAKEWORD(2, 0), &WSAData))
	{
		if (!gethostname(hostName, sizeof(hostName)))
		{
			hostent* host = (hostent*)gethostbyname(hostName);
			if (host != NULL)
			{
				return inet_ntoa(*(struct in_addr*)*host->h_addr_list);
			}
		}
	}
	return "Get IP failed.";
}


#include <Windows.h>
//将string转换成wstring  
wstring string2wstring(string str)
{
	wstring result;
	//获取缓冲区大小，并申请空间，缓冲区大小按字符计算  
	int len = MultiByteToWideChar(CP_ACP, 0, str.c_str(), str.size(), NULL, 0);
	TCHAR* buffer = new TCHAR[len + 1];
	//多字节编码转换成宽字节编码  
	MultiByteToWideChar(CP_ACP, 0, str.c_str(), str.size(), buffer, len);
	buffer[len] = '\0';             //添加字符串结尾  
	//删除缓冲区并返回值  
	result.append(buffer);
	delete[] buffer;
	return result;
}

//将wstring转换成string  
string wstring2string(wstring wstr)
{
	string result;
	//获取缓冲区大小，并申请空间，缓冲区大小事按字节计算的  
	int len = WideCharToMultiByte(CP_ACP, 0, wstr.c_str(), wstr.size(), NULL, 0, NULL, NULL);
	char* buffer = new char[len + 1];
	//宽字节编码转换成多字节编码  
	WideCharToMultiByte(CP_ACP, 0, wstr.c_str(), wstr.size(), buffer, len, NULL, NULL);
	buffer[len] = '\0';
	//删除缓冲区并返回值  
	result.append(buffer);
	delete[] buffer;
	return result;
}



TCHAR* CharToTCHAR(const char* pChar)
{
	TCHAR* pTchar = nullptr;
	int nLen = strlen(pChar) + 1;
	pTchar = new wchar_t[nLen];
	MultiByteToWideChar(CP_ACP, 0, pChar, nLen, pTchar, nLen);
	return pTchar;
}

char* TCHARToChar(TCHAR* pTchar)
{
	char* pChar = nullptr;
	int nLen = wcslen(pTchar) + 1;
	pChar = new char[nLen * 2];
	WideCharToMultiByte(CP_ACP, 0, pTchar, nLen, pChar, 2 * nLen, NULL, NULL);
	return pChar;
}


vector<string> split(const string& str, const string& delim) {
	vector<string> res;
	if ("" == str) return res;
	//先将要切割的字符串从string类型转换为char*类型
	char* strs = new char[str.length() + 1]; //不要忘了
	strcpy(strs, str.c_str());

	char* d = new char[delim.length() + 1];
	strcpy(d, delim.c_str());

	char* p = strtok(strs, d);
	while (p) {
		string s = p; //分割得到的字符串转换为string类型
		res.push_back(s); //存入结果数组
		p = strtok(NULL, d);
	}

	return res;
}

std::wstring s2ws(const std::string& s)
{
	int len;
	int slength = (int)s.length() + 1;
	len = MultiByteToWideChar(CP_ACP, 0, s.c_str(), slength, 0, 0);
	wchar_t* buf = new wchar_t[len];
	MultiByteToWideChar(CP_ACP, 0, s.c_str(), slength, buf, len);
	std::wstring r(buf);
	delete[] buf;
	return r;
}


int RunCmd(const std::string& name, const std::string& cmd, int& code, std::string& out) {
	SECURITY_ATTRIBUTES sa;
	HANDLE hRead, hWrite;
	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.lpSecurityDescriptor = NULL;
	sa.bInheritHandle = TRUE;

	if (!CreatePipe(&hRead, &hWrite, &sa, 0)) {
		DWORD ret = GetLastError();
		return ret ? ret : -1;
	}

	STARTUPINFOA si;
	PROCESS_INFORMATION pi;
	ZeroMemory(&si, sizeof(STARTUPINFO));

	si.cb = sizeof(STARTUPINFO);
	GetStartupInfoA(&si);
	si.hStdError = hWrite;
	si.hStdOutput = hWrite;
	si.wShowWindow = SW_HIDE;
	si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;

	char cmdline[0x1000] = { 0 };
	sprintf(cmdline, "%s", cmd.c_str());
	if (!CreateProcessA(name.c_str(), cmdline, NULL, NULL, TRUE, NULL,
		NULL, NULL, &si, &pi)) {
		DWORD ret = GetLastError();
		printf("%d\n", ret);
		CloseHandle(hRead);
		CloseHandle(hWrite);
		return ret ? ret : -1;
	}

	CloseHandle(hWrite);
	char buffer[4096] = { 0 };
	DWORD bytesRead;
	while (true) {
		if (!ReadFile(hRead, buffer, 4095, &bytesRead, NULL)) break;
		out.append(buffer, bytesRead);
		Sleep(100);
	}

	DWORD exitCode = 0;
	GetExitCodeProcess(pi.hProcess, &exitCode);
	code = exitCode;
	CloseHandle(hRead);
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);
	return 0;
}

void* scan(string string_dir)
{
	cout << "scaning path: " << string_dir << endl;
	string param = " therule.yar " + string_dir;



	std::wstring stemp = s2ws(param);
	LPCWSTR result = stemp.c_str();
	//wcout << result << endl;

	int code1 = 0;
	string  out1;


	RunCmd("yara64.exe", param, code1, out1);
	//cout << out1 << endl;



	while (strstr(out1.c_str(), "warning"))
	{
		out1 = out1.substr(out1.find("\n") + 1);
	}



	if (strstr(out1.c_str(), "Hunting"))
	{
		cout << out1 << endl;


		LPWSTR name = new WCHAR[MAX_PATH];
		LPDWORD namesize = new DWORD[MAX_PATH];
		GetComputerName(name, namesize);
		string resultpath = TCHARToChar(name);
		resultpath = resultpath + "_" + getIP() + "_" + ".txt";

		FILE* fp = NULL;
		fp = fopen(resultpath.c_str(), "a+");  //创建文件
		if (NULL == fp)
		{
			cout << "create file fault" << endl;
			return 0;
		}
		fprintf(fp, "%s\n", out1.c_str());
		fclose(fp);
		fp = NULL;//需要指向空，否则会指向原打开文件地址    
	}
}



bool ListFiles(wstring path, wstring mask, vector<wstring>& files) {
	HANDLE hFind = INVALID_HANDLE_VALUE;
	WIN32_FIND_DATA ffd;
	wstring spec;
	stack<wstring> directories;

	directories.push(path);
	files.clear();

	while (!directories.empty()) {
		path = directories.top();
		spec = path + L"\\" + mask;
		directories.pop();

		hFind = FindFirstFile(spec.c_str(), &ffd);
		if (hFind == INVALID_HANDLE_VALUE) {
			return false;
		}

		do {
			if (wcscmp(ffd.cFileName, L".") != 0 &&
				wcscmp(ffd.cFileName, L"..") != 0) {
				if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
					directories.push(path + L"\\" + ffd.cFileName);
				}
				else {

					string fileName = wstring2string(ffd.cFileName);
					string suffix_str = fileName.substr(fileName.find_last_of('.') + 1);
					if (strstr(suffix_str.c_str(), "exe") || strstr(suffix_str.c_str(), "dll"))
					{
						files.push_back(path + L"\\" + ffd.cFileName);
					}

					//files.push_back(path + L"\\" + ffd.cFileName);
				}
			}
		} while (FindNextFile(hFind, &ffd) != 0);

		if (GetLastError() != ERROR_NO_MORE_FILES) {
			FindClose(hFind);
			return false;
		}

		FindClose(hFind);
		hFind = INVALID_HANDLE_VALUE;
	}

	return true;
}


int main(int argc, const char* argv[]) {

	std::cout << "packyara_MultiThread.exe path threadnumber\n";
	std::cout << "ListFile Start!\n";
	std::cout << "thread number: " <<  atoi(argv[2]) << "\n";


	std::vector<std::wstring> dir;


	SetConsoleOutputCP(65001);
	ifstream in(argv[1]);
	string line;
	if (in) // 有该文件
	{
		while (getline(in, line)) // line中不包括每行的换行符
		{
			dir.push_back(string2wstring(line));
		}
	}
	else // 没有该文件
	{
		cout << "no QueryPath.txt file" << endl;
	}

	vector<wstring> files;

	threadpool_t pool;
	//初始化线程池，最多三个线程
	threadpool_init(&pool, atoi(argv[2]));

	for (unsigned int i = 0; i < dir.size(); ++i)
	{
		//cout << dir[i] << endl;
		
		ListFiles(dir[i], L"*" ,files);
		for (unsigned int j = 0; j < files.size(); ++j)
		{
			//scan("\""+ wstring2string(files[j])+ "\"");
			threadpool_add_task(&pool, scan, "\"" + wstring2string(files[j]) + "\"");
		}
		
	}

	threadpool_destroy(&pool);

	std::cout << "over \n";
	return 0;
}
