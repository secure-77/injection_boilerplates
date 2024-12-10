// dllmain.cpp : Definiert den Einstiegspunkt für die DLL-Anwendung.
#include "pch.h"
#include "Windows.h"
#include <detours.h>



typedef BOOL(WINAPI* WRITE_FILE)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);

WRITE_FILE OriginalWriteFile = NULL;


BOOL WINAPI MyWriteFile(HANDLE filehandle, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped) {
    MessageBox(NULL, L"file write hooked", L"hook", 0);
    return OriginalWriteFile(filehandle, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
}


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
        MessageBox(NULL, L"DLL injected", L"test", 0);

        OriginalWriteFile = (WRITE_FILE)GetProcAddress(GetModuleHandleA("kernel32.dll"), "WriteFile");
        if (!OriginalWriteFile) {
            MessageBox(NULL, L"failed to find write file function", L"error", 0);
            return 1;
        }

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)OriginalWriteFile, MyWriteFile);
        if (DetourTransactionCommit() != NO_ERROR) {
            MessageBox(NULL, L"detour failed", L"error", 0);
            return 1;
        }



    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

