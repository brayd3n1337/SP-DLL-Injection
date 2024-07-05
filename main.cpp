#include <windows.h>
#include <tchar.h>
#include <iostream>

#define ERROR(x) std::cerr << "[INFO] " << x << '\n';
#define INFO(x) std::cout << "[INFO] " << x << '\n';

BOOL Inject(const std::string& processPath, const std::string& dllPath)
{
    STARTUPINFOA si = { sizeof(STARTUPINFOA) };
    PROCESS_INFORMATION pi;

    // creates a suspended process which allows us to inject the DLL
    if (!CreateProcessA(nullptr,
                        (LPSTR) processPath.c_str(),
                        nullptr,
                        nullptr,
                        FALSE,
                        CREATE_SUSPENDED,
                        nullptr,
                        nullptr,
                        &si,
                        &pi))
    {

        ERROR("failed to create the suspended process: " << GetLastError())

        return FALSE;
    }

    INFO("suspended process created successfully.")

    // allocate dll path memory in the target process
    LPVOID pDllPath = VirtualAllocEx(
            pi.hProcess,
            nullptr,
            strlen(dllPath.c_str()) + 1,
            MEM_COMMIT,
            PAGE_READWRITE);

    if (pDllPath == nullptr)
    {
        ERROR("failed to write memory to the target process: " << GetLastError())

        // close the process
        TerminateProcess(pi.hProcess, 1);
        return FALSE;
    }

    INFO("mem allocated successfully.")

    // Write the DLL path into the allocated memory
    if (!WriteProcessMemory(
            pi.hProcess,
            pDllPath,
            (LPVOID) dllPath.c_str(),
            strlen(dllPath.c_str()) + 1,
            nullptr))
    {
        ERROR("wpm failed: " << GetLastError())

        // clean up
        VirtualFreeEx(pi.hProcess, pDllPath, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        return FALSE;
    }

    INFO("dll path written to memory successfully.")

    // get the LLA function by getting the kernel32.dll handle
    auto pLoadLibrary = (LPVOID) GetProcAddress(
            GetModuleHandleA("kernel32.dll"),
            "LoadLibraryA");

    if (pLoadLibrary == nullptr)
    {
        ERROR("failed 2 get proc address: " << GetLastError())

        // clean up
        VirtualFreeEx(pi.hProcess, pDllPath, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        return FALSE;
    }

    INFO("LLA function retrieved successfully.")

    // create the remote thread handle to create a new thread
    // on the executable for the DLL injection
    HANDLE hThread = CreateRemoteThread(
            pi.hProcess,
            nullptr,
            0,
            (LPTHREAD_START_ROUTINE) pLoadLibrary,
            pDllPath,
            0,
            nullptr);

    if (hThread == nullptr)
    {
        ERROR("CRT failed: " << GetLastError())

        // clean up
        VirtualFreeEx(pi.hProcess, pDllPath, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        return FALSE;
    }

    INFO("remote thread created successfully.")

    INFO("waiting for the remote thread to finish...")

    // wait for the remote thread to finish
    WaitForSingleObject(hThread, INFINITE);

    INFO("remote thread finished. cleaning up...")

    // clean up
    VirtualFreeEx(pi.hProcess, pDllPath, 0, MEM_RELEASE);
    CloseHandle(hThread);

    // continue the thread of the target process
    ResumeThread(pi.hThread);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    INFO("cleaned up successfully.")

    return TRUE;
}

int main()
{
    const std::string processPath = R"("pathtoexe")";
    const std::string dllPath = R"("pathtodll"))";

    if (Inject(processPath, dllPath))
    {
        INFO("DLL injection succeeded.")
        return 0;
    }


    ERROR("DLL injection failed.")

    return 1;
}
