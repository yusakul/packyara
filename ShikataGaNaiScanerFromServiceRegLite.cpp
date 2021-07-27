#include <time.h> 
#include <windows.h> 
#include <iostream>
#include <stdio.h>  
#include <tchar.h>  
#include <fstream>
#include <queue>
#include <string.h>
#include <cstring>

#include <vector>


using namespace std;

#define MAX_KEY_LENGTH 255  
#define MAX_VALUE_NAME 16383  
DWORD dwType = REG_BINARY | REG_DWORD | REG_EXPAND_SZ | REG_MULTI_SZ | REG_NONE | REG_SZ;
std::queue<std::wstring> keystack;

//#define COMMAND_OUTPUT

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

void query(HKEY rootKey, const wchar_t* path)
{
#ifdef COMMAND_OUTPUT
	_tprintf(TEXT("\nProcess: %s :\n"), path);
#endif
	HKEY hKey;
	if (RegOpenKeyEx(rootKey, path, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
	{
		RegCloseKey(hKey);
		return;
	}

	TCHAR    achKey[MAX_KEY_LENGTH];   // buffer for subkey name  
	DWORD    cbName;                   // size of name string   
	TCHAR    achClass[MAX_PATH] = TEXT("");  // buffer for class name   
	DWORD    cchClassName = MAX_PATH;  // size of class string   
	DWORD    cSubKeys = 0;               // number of subkeys   
	DWORD    cbMaxSubKey;              // longest subkey size   
	DWORD    cchMaxClass;              // longest class string   
	DWORD    cValues;              // number of values for key   
	DWORD    cchMaxValue;          // longest value name   
	DWORD    cbMaxValueData;       // longest value data   
	DWORD    cbSecurityDescriptor; // size of security descriptor   
	FILETIME ftLastWriteTime;      // last write time   

	DWORD i, retCode;

	TCHAR  achValue[MAX_VALUE_NAME];
	DWORD cchValue = MAX_VALUE_NAME;

	// Get the class name and the value count.   
	retCode = RegQueryInfoKey(
		hKey,                    // key handle   
		achClass,                // buffer for class name   
		&cchClassName,           // size of class string   
		NULL,                    // reserved   
		&cSubKeys,               // number of subkeys   
		&cbMaxSubKey,            // longest subkey size   
		&cchMaxClass,            // longest class string   
		&cValues,                // number of values for this key   
		&cchMaxValue,            // longest value name   
		&cbMaxValueData,         // longest value data   
		&cbSecurityDescriptor,   // security descriptor   
		&ftLastWriteTime);       // last write time   

	// Enumerate the subkeys, until RegEnumKeyEx fails.  
	if (cSubKeys)
	{
#ifdef COMMAND_OUTPUT
		printf("Number of subkeys: %d\n", cSubKeys);
#endif
		for (i = 0; i < cSubKeys; i++)
		{
			cbName = MAX_KEY_LENGTH;
			retCode = RegEnumKeyEx(hKey, i,
				achKey,
				&cbName,
				NULL,
				NULL,
				NULL,
				&ftLastWriteTime);
			if (retCode == ERROR_SUCCESS)
			{
#ifdef COMMAND_OUTPUT
				_tprintf(TEXT("(%d) %s\n"), i + 1, achKey);
#endif
				//use achKey to build new path and input it into stack.
				std::wstring newPath = L"";
				newPath.append(path);
				newPath.append(L"\\");
				newPath.append(achKey);
				keystack.push(newPath);
			}
		}
	}

	// Enumerate the key values.   
	if (cValues)
	{
#ifdef COMMAND_OUTPUT
		printf("Number of values: %d\n", cValues);
#endif
		for (i = 0, retCode = ERROR_SUCCESS; i < cValues; i++)
		{
			cchValue = MAX_VALUE_NAME;
			achValue[0] = '\0';
			unsigned char vari[70] = {};
			retCode = RegEnumValue(hKey, i,
				achValue,
				&cchValue,
				NULL,
				NULL,
				NULL,
				NULL);
			if (retCode == ERROR_SUCCESS)
			{
				TCHAR szBuffer[255] = { 0 };
				DWORD dwNameLen = 255;
				DWORD rQ = RegQueryValueEx(hKey, achValue, 0, &dwType, (LPBYTE)szBuffer, &dwNameLen);
				if (rQ == ERROR_SUCCESS)
				{
					//_tprintf(TEXT("(%d) %s %s\n"), i + 1, achValue, szBuffer);
				}
				char* dir = TCHARToChar(szBuffer);
				if (!strcmp("ImagePath", TCHARToChar(achValue)))
				{
					if (dir[0] == '"' && dir[1] != '%' || dir[0] == 'C' && dir[1] != '%' || dir[0] == 'c' && dir[1] != '%')
					{
						std::string string_dir = dir;
						std::vector<string> res = split(string_dir, "\"");
						for (int i = 0; i < res.size(); ++i)
						{
							//cout << res[i] << endl;
						}
						string string_dir_1 = res[0];
						string rerr = string_dir_1.substr(0, string_dir_1.rfind("\\"));
						cout << "scaning path: " << rerr << endl;
						string param = " rule.yar \"" + rerr + "\"";
						if (!_stricmp(rerr.c_str(), "C:\Windows\System32") || !_stricmp(rerr.c_str(), "C:\\Windows\\System32"))
						{
							cout << "jmp over: " << rerr << endl;
							continue;
						}
						if (!_stricmp(rerr.c_str(), "C:\Windows\SysWOW64") || !_stricmp(rerr.c_str(), "C:\\Windows\\System32"))
						{
							cout << "jmp over: " << rerr << endl;
							continue;
						}


						std::wstring stemp = s2ws(param);
						LPCWSTR result = stemp.c_str();
						//wcout << result << endl;

						int code1 = 0;
						string  out1;

						RunCmd("yara64.exe", param, code1, out1);
						//cout << out1 << endl;

						if (strstr(out1.c_str(), "ShikataGaNai"))
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
								continue;
							}
							fprintf(fp, "%s\n", out1.c_str());
							fclose(fp);
							fp = NULL;//需要指向空，否则会指向原打开文件地址    
						}
					}

				}
			}
		}
	}
	//release.
	RegCloseKey(hKey);
}

void query2(HKEY rootKey, const wchar_t* path)
{
#ifdef COMMAND_OUTPUT
	_tprintf(TEXT("\nProcess: %s :\n"), path);
#endif
	HKEY hKey;
	if (RegOpenKeyEx(rootKey, path, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
	{
		RegCloseKey(hKey);
		return;
	}

	TCHAR    achKey[MAX_KEY_LENGTH];   // buffer for subkey name  
	DWORD    cbName;                   // size of name string   
	TCHAR    achClass[MAX_PATH] = TEXT("");  // buffer for class name   
	DWORD    cchClassName = MAX_PATH;  // size of class string   
	DWORD    cSubKeys = 0;               // number of subkeys   
	DWORD    cbMaxSubKey;              // longest subkey size   
	DWORD    cchMaxClass;              // longest class string   
	DWORD    cValues;              // number of values for key   
	DWORD    cchMaxValue;          // longest value name   
	DWORD    cbMaxValueData;       // longest value data   
	DWORD    cbSecurityDescriptor; // size of security descriptor   
	FILETIME ftLastWriteTime;      // last write time   

	DWORD i, retCode;

	TCHAR  achValue[MAX_VALUE_NAME];
	DWORD cchValue = MAX_VALUE_NAME;

	// Get the class name and the value count.   
	retCode = RegQueryInfoKey(
		hKey,                    // key handle   
		achClass,                // buffer for class name   
		&cchClassName,           // size of class string   
		NULL,                    // reserved   
		&cSubKeys,               // number of subkeys   
		&cbMaxSubKey,            // longest subkey size   
		&cchMaxClass,            // longest class string   
		&cValues,                // number of values for this key   
		&cchMaxValue,            // longest value name   
		&cbMaxValueData,         // longest value data   
		&cbSecurityDescriptor,   // security descriptor   
		&ftLastWriteTime);       // last write time   

	// Enumerate the subkeys, until RegEnumKeyEx fails.  
	if (cSubKeys)
	{
#ifdef COMMAND_OUTPUT
		printf("Number of subkeys: %d\n", cSubKeys);
#endif
		for (i = 0; i < cSubKeys; i++)
		{
			cbName = MAX_KEY_LENGTH;
			retCode = RegEnumKeyEx(hKey, i,
				achKey,
				&cbName,
				NULL,
				NULL,
				NULL,
				&ftLastWriteTime);
			if (retCode == ERROR_SUCCESS)
			{
#ifdef COMMAND_OUTPUT
				_tprintf(TEXT("(%d) %s\n"), i + 1, achKey);
#endif
				//use achKey to build new path and input it into stack.
				std::wstring newPath = L"";
				newPath.append(path);
				newPath.append(L"\\");
				newPath.append(achKey);
				keystack.push(newPath);
			}
		}
	}

	// Enumerate the key values.   
	if (cValues)
	{
#ifdef COMMAND_OUTPUT
		printf("Number of values: %d\n", cValues);
#endif
		for (i = 0, retCode = ERROR_SUCCESS; i < cValues; i++)
		{
			cchValue = MAX_VALUE_NAME;
			achValue[0] = '\0';
			unsigned char vari[70] = {};
			retCode = RegEnumValue(hKey, i,
				achValue,
				&cchValue,
				NULL,
				NULL,
				NULL,
				NULL);
			if (retCode == ERROR_SUCCESS)
			{
				TCHAR szBuffer[255] = { 0 };
				DWORD dwNameLen = 255;
				DWORD rQ = RegQueryValueEx(hKey, achValue, 0, &dwType, (LPBYTE)szBuffer, &dwNameLen);
				if (rQ == ERROR_SUCCESS)
				{
					//_tprintf(TEXT("(%d) %s %s\n"), i + 1, achValue, szBuffer);
				}
				char* dir = TCHARToChar(szBuffer);
				if (dir[0] == '"' && dir[1] != '%' || dir[0] == 'C' && dir[1] != '%' || dir[0] == 'c' && dir[1] != '%')
				{
					std::string string_dir = dir;
					std::vector<string> res = split(string_dir, "\"");
					for (int i = 0; i < res.size(); ++i)
					{
						//cout << res[i] << endl;
					}
					string string_dir_1 = res[0];
					string rerr = string_dir_1.substr(0, string_dir_1.rfind("\\"));
					cout << "scaning path: " << rerr << endl;
					string param = " rule.yar \"" + rerr + "\"";
					if (!_stricmp(rerr.c_str(), "C:\Windows\System32") || !_stricmp(rerr.c_str(), "C:\\Windows\\System32"))
					{
						cout << "jmp over: " << rerr << endl;
						continue;
					}
					if (!_stricmp(rerr.c_str(), "C:\Windows\SysWOW64") || !_stricmp(rerr.c_str(), "C:\\Windows\\System32"))
					{
						cout << "jmp over: " << rerr << endl;
						continue;
					}


					std::wstring stemp = s2ws(param);
					LPCWSTR result = stemp.c_str();
					//wcout << result << endl;

					int code1 = 0;
					string  out1;

					RunCmd("yara64.exe", param, code1, out1);
					//cout << out1 << endl;

					if (strstr(out1.c_str(), "ShikataGaNai"))
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
							continue;
						}
						fprintf(fp, "%s\n", out1.c_str());
						fclose(fp);
						fp = NULL;//需要指向空，否则会指向原打开文件地址    
					}
				}
			}
		}
	}
	//release.
	RegCloseKey(hKey);
}


void regQuery(HKEY beginKey, TCHAR* path)
{
	//Begin to get HKEY of path.
	query(beginKey, path);
	while (!keystack.empty())
	{
		std::wstring newPath = keystack.front();
		keystack.pop();
		query(beginKey, newPath.c_str());
	}

	//Release.
	RegCloseKey(beginKey);
}

void regQuery2(HKEY beginKey, TCHAR* path)
{
	//Begin to get HKEY of path.
	query(beginKey, path);
	while (!keystack.empty())
	{
		std::wstring newPath = keystack.front();
		keystack.pop();
		query2(beginKey, newPath.c_str());
	}

	//Release.
	RegCloseKey(beginKey);
}

int _tmain(int argc, _TCHAR* argv[])
{
	cout << "create by yusakul, detect by yara" << endl;
	TCHAR* services = CharToTCHAR("SYSTEM\\CurrentControlSet\\services");
	regQuery(HKEY_LOCAL_MACHINE, services);
	TCHAR* run = CharToTCHAR("SOFTWARE\\MICROSOFT\\Windows\\CurrentVersion\\Run");
	regQuery2(HKEY_LOCAL_MACHINE, run);
	system("pause");
	return 0;
}