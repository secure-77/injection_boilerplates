#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include <string.h>
#include <tlhelp32.h>


#define TARGET_PROCESS_NAME L"explorer.exe"

#define TARGET_MODULE_NAME "KERNELBASE.dll"
#define TARGET_FUNCTION_NAME "CopyFile2"



DWORD FindProcessPID()
{
    PROCESSENTRY32 pe32;
    HANDLE hProcessSnap;

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
        if (wcscmp(pe32.szExeFile, TARGET_PROCESS_NAME) == 0) {
            wprintf(L"Found process: %s\n", pe32.szExeFile);
            CloseHandle(hProcessSnap);
            return pe32.th32ProcessID;
        }
    } while (Process32Next(hProcessSnap, &pe32));

    printf("Explorer.exe not found.\n");
    CloseHandle(hProcessSnap);
    return 0;
}

int GetFunctionAddressInTargetProcess(DWORD targetProcessId)
{
    
    // Open the target process
    HANDLE hTargetProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetProcessId);
    if (!hTargetProcess) {
        printf("Failed to open target process. Error: %lu\n", GetLastError());
        return 0;
    }

    // Get a list of modules in the target process
    HMODULE hModules[1024];
    DWORD cbNeeded;
    if (!EnumProcessModules(hTargetProcess, hModules, sizeof(hModules), &cbNeeded)) {
        printf("Failed to enumerate modules in target process. Error: %lu\n", GetLastError());
        CloseHandle(hTargetProcess);
        return 0;
    }

    size_t moduleCount = cbNeeded / sizeof(HMODULE);
    HMODULE hTargetModule = NULL;

    // Find the target module
    for (size_t i = 0; i < moduleCount; ++i) {
        char szModuleName[MAX_PATH];
        if (GetModuleBaseNameA(hTargetProcess, hModules[i], szModuleName, sizeof(szModuleName))) {

            if (strcmp(TARGET_MODULE_NAME, szModuleName) == 0) {
                hTargetModule = hModules[i];
                printf("Module found: %s\n", szModuleName);
                break;
            }
        }
    }

    if (!hTargetModule) {
        printf("Target module not found in target process.\n");
        CloseHandle(hTargetProcess);
        return 0;
    }

    // Load the module locally with DONT_RESOLVE_DLL_REFERENCES
    HMODULE hLocalModule = LoadLibraryExA(TARGET_MODULE_NAME, NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (!hLocalModule) {
        printf("Failed to load module locally. Error: %lu\n", GetLastError());
        CloseHandle(hTargetProcess);
        return 0;
    }

    // Get the address of the function locally
    FARPROC localFuncAddress = GetProcAddress(hLocalModule, TARGET_FUNCTION_NAME);
    if (!localFuncAddress) {
        printf("Failed to get function address locally. Error: %lu\n", GetLastError());
        FreeLibrary(hLocalModule);
        CloseHandle(hTargetProcess);
        return 0;
    }

    // Calculate the offset of the function in the module
    ptrdiff_t funcOffset = (BYTE*)localFuncAddress - (BYTE*)hLocalModule;

    printf("Offset: %td\n", funcOffset);


    // Calculate the address of the function in the target process
    
    void* outFunctionAddress;   
    outFunctionAddress = (void*)((BYTE*)hTargetModule + funcOffset);
    printf("Function address in target process: %p\n", outFunctionAddress);

    // Clean up
    FreeLibrary(hLocalModule);
    CloseHandle(hTargetProcess);

    return 1;
}



int main() {


    DWORD targetProcessId = FindProcessPID(); // Replace with the target process ID

    if (GetFunctionAddressInTargetProcess(targetProcessId)) {
        printf("Successfully retrieved function address");
    }
    else {
        printf("Failed to retrieve function address.\n");
    }

    return 0;
}
