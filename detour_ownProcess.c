#include <windows.h>
#include <detours.h>
#include <stdio.h>

typedef BOOL(WINAPI* COPY_FILE)(LPCWSTR, LPCWSTR, BOOL);

// Pointer to the original CopyFile function
COPY_FILE OriginalCopyFile = NULL;

// Hooked CopyFile function
BOOL WINAPI MyCopyFile(LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName, BOOL bFailIfExists) {
    wprintf(L"CopyFile Hooked: %s -> %s\n", lpExistingFileName, lpNewFileName);
    return OriginalCopyFile(lpExistingFileName, lpNewFileName, bFailIfExists);
}

int main() {
    // Detour setup
    OriginalCopyFile = (COPY_FILE)GetProcAddress(GetModuleHandleA("kernel32.dll"), "CopyFile");
    if (!OriginalCopyFile) {
        printf("Failed to locate CopyFileW.\n");
        return 1;
    }

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&(PVOID)OriginalCopyFile, MyCopyFile);
    if (DetourTransactionCommit() != NO_ERROR) {
        printf("Detour failed.\n");
        return 1;
    }

    // Test the hook
    CopyFileW(L"test.txt", L"copy_test.txt", FALSE);

    // Remove the hook
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourDetach(&(PVOID)OriginalCopyFile, MyCopyFile);
    DetourTransactionCommit();

    return 0;
}
