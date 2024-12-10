// dllmain.cpp : Definiert den Einstiegspunkt für die DLL-Anwendung.
#include "pch.h"
#include "Windows.h"
#include "detours.h"



typedef HRESULT(WINAPI* COPY_FILE2)(PCWSTR, PCWSTR, COPYFILE2_EXTENDED_PARAMETERS);


COPY_FILE2 TrueCopyFile2 = NULL; 

HRESULT WINAPI MyCopyFile(PCWSTR pwszExistingFileName, PCWSTR pwszNewFileName, COPYFILE2_EXTENDED_PARAMETERS pExtendedParameters) {
    


    size_t len = wcslen(pwszExistingFileName);

    // cancel file copy for js files
    if (len > 3 && _wcsicmp(&pwszExistingFileName[len - 3], L".js") == 0)
    {
        
        return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND); // Simulate file copy failure       
        
    }

    HRESULT ret = TrueCopyFile2(pwszExistingFileName, pwszNewFileName, pExtendedParameters); 
    return ret;
 
    }


int initHook() {
    
    TrueCopyFile2 = (COPY_FILE2)GetProcAddress(GetModuleHandleA("kernelbase.dll"), "CopyFile2");
    if (!TrueCopyFile2) {
        MessageBox(NULL, L"failed to find write file function", L"error", 0);
        return 1;
    }

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&(PVOID&)TrueCopyFile2, MyCopyFile);
    if (DetourTransactionCommit() != NO_ERROR) {
        MessageBox(NULL, L"detour failed", L"error", 0);
        return 1;
    }
}



BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        initHook();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

