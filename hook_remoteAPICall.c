#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include <string.h>
#include <tlhelp32.h>



#define TARGET_PROCESS_NAME L"explorer.exe"

#define TARGET_MODULE_NAME "KERNEL32.DLL"
//#define TARGET_MODULE_NAME "KERNELBASE.dll"
#define TARGET_FUNCTION_NAME "CopyFile2"

#define INJECT_FUNCTION_NAME "MyCopyFile2"


// Function pointer for CopyFile2
typedef HRESULT(WINAPI* COPY_FILE_2)(
    _In_      PCWSTR                          pwszExistingFileName,
    _In_      PCWSTR                          pwszNewFileName,
    _In_opt_  COPYFILE2_EXTENDED_PARAMETERS* pExtendedParameters
    );

// Declare the original function pointer (this will be used by DetourAttach)
COPY_FILE_2 OriginalCopyFile2 = NULL;

// Our custom hook function
HRESULT WINAPI MyCopyFile2(
    _In_      PCWSTR                          pwszExistingFileName,
    _In_      PCWSTR                          pwszNewFileName,
    _In_opt_  COPYFILE2_EXTENDED_PARAMETERS* pExtendedParameters
)
{
    size_t len = wcslen(pwszExistingFileName);
    if (len > 4 && _wcsicmp(&pwszExistingFileName[len - 4], L".docx") == 0)
    {
        wprintf(L"Cancelling file copy for: %s\n", pwszExistingFileName);
        return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND); // Simulate file copy failure
    }

    // Call the original CopyFile2 if not a .docx file
    return OriginalCopyFile2(pwszExistingFileName, pwszNewFileName, pExtendedParameters);
}

DWORD FindExplorerPID()
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


char GetAssemblyCode() {

    // Get the address of my local function
    void* localFuncAddress = &MyCopyFile2;

    printf("JMP to inject function in own process at: %p\n", localFuncAddress);

    char injectFunctionJMPBytes[6] = "";
    SIZE_T bytesRead = 0;

    // save the first 6 bytes of the original MessageBoxA function - will need for unhooking
    ReadProcessMemory(GetCurrentProcess(), localFuncAddress, injectFunctionJMPBytes, 6, &bytesRead);

    LPVOID targetAddress = NULL;

    for (int i = 0; i < bytesRead; i++) {
        printf("%02X ", (unsigned char)injectFunctionJMPBytes[i]);
    }
    printf("\n");


    if ((unsigned char)injectFunctionJMPBytes[0] == 0xE9) {  // Relative JMP
        int relativeOffset = *(int*)&injectFunctionJMPBytes[1];
        targetAddress = (LPVOID)((BYTE*)localFuncAddress + 5 + relativeOffset); // 5 = size of E9 instruction
        printf("Resolved JMP Target: %p\n", targetAddress);
    }
    else {
        printf("No JMP instruction found at the address.\n");
    }

    // TO DO: find dynamic the ret address to calculate the payload size

    char injectFunctionBytes[0xB0] = "";
    bytesRead = 0;
    ReadProcessMemory(GetCurrentProcess(), targetAddress, injectFunctionBytes, sizeof(injectFunctionBytes), &bytesRead);


    // print the byte array at target memory address
    for (int i = 0; i < bytesRead; i++) {
        printf("%02X ", (unsigned char)injectFunctionBytes[i]);
    }
    printf("\n");


    return injectFunctionBytes;

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

    char copyFileOriginalBytes[6] = "";
    SIZE_T bytesRead = 0;

    // save the first 6 bytes of the original MessageBoxA function - will need for unhooking
    ReadProcessMemory(hTargetProcess, outFunctionAddress, copyFileOriginalBytes, 6, &bytesRead);

    // print the byte array at target memory address
    for (int i = 0; i < 6; i++) {
        printf("%02X ", (unsigned char)copyFileOriginalBytes[i]);
    }
    printf("\n");


    // injected function shell code
    unsigned char shellcode = GetAssemblyCode();


    PVOID remoteBuffer; 
    remoteBuffer = VirtualAllocEx(hTargetProcess, NULL, sizeof shellcode, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE); 

    WriteProcessMemory(hTargetProcess, remoteBuffer, shellcode, sizeof shellcode, NULL);


    //void* hookedcopyFile2 = &MyCopyFile2; 
    char patch[6] = { 0 }; 
    memcpy_s(patch, 1, "\x68", 1); 
    memcpy_s(patch + 1, 4, &remoteBuffer, 4); 
    memcpy_s(patch + 5, 1, "\xC3", 1); 

    SIZE_T bytesWritten = 0; 
    WriteProcessMemory(hTargetProcess, (LPVOID)outFunctionAddress, patch, sizeof(patch), &bytesWritten);

    getchar();
    //bytesWritten = 0;


    // Restore original function
    WriteProcessMemory(hTargetProcess, (LPVOID)outFunctionAddress, copyFileOriginalBytes, sizeof(copyFileOriginalBytes), &bytesWritten);


    // Clean up
    FreeLibrary(hLocalModule);
    CloseHandle(hTargetProcess);

    return 1;
}








int main() {


    DWORD targetProcessId = FindExplorerPID(); // Replace with the target process ID

    
    if (GetFunctionAddressInTargetProcess(targetProcessId)) {
        printf("Successfully retrieved function address");
    }
    else {
        printf("Failed to retrieve function address.\n");
    }

    return 0;
}
