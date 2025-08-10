#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include <fcntl.h>
#include <io.h>
#include <filesystem>

namespace fs = std::filesystem;

// Function to get process information by PID
bool GetProcessInfoByPID(DWORD pid, PROCESSENTRY32& outProcInfo) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32 procEntry = { 0 };
    procEntry.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(snapshot, &procEntry)) {
        do {
            if (procEntry.th32ProcessID == pid) {
                outProcInfo = procEntry;
                CloseHandle(snapshot);
                return true;
            }
        } while (Process32Next(snapshot, &procEntry));
    }

    CloseHandle(snapshot);
    return false;
}

// DLL injection function
bool InjectDLL(DWORD processID, const std::wstring& dllPath) {
    std::wcout << L"[+] Injecting DLL: " << dllPath << L" into PID: " << processID << std::endl;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
    if (!hProcess) {
        std::wcerr << L"[-] OpenProcess failed. Error: " << GetLastError() << std::endl;
        return false;
    }

    SIZE_T allocSize = (dllPath.size() + 1) * sizeof(wchar_t);
    LPVOID pRemoteMemory = VirtualAllocEx(hProcess, NULL, allocSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemoteMemory) {
        std::wcerr << L"[-] VirtualAllocEx failed. Error: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return false;
    }

    if (!WriteProcessMemory(hProcess, pRemoteMemory, dllPath.c_str(), allocSize, NULL)) {
        std::wcerr << L"[-] WriteProcessMemory failed. Error: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    HMODULE hKernel32 = GetModuleHandle(L"kernel32.dll");
    if (!hKernel32) {
        std::wcerr << L"[-] GetModuleHandle failed." << std::endl;
        return false;
    }

    LPTHREAD_START_ROUTINE pLoadLibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryW");
    if (!pLoadLibrary) {
        std::wcerr << L"[-] GetProcAddress failed." << std::endl;
        return false;
    }

    HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, pLoadLibrary, pRemoteMemory, 0, NULL);
    if (!hRemoteThread) {
        std::wcerr << L"[-] CreateRemoteThread failed. Error: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    WaitForSingleObject(hRemoteThread, INFINITE);
    VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
    CloseHandle(hRemoteThread);
    CloseHandle(hProcess);

    return true;
}

int wmain() {
    _setmode(_fileno(stdout), _O_U16TEXT);
    _setmode(_fileno(stderr), _O_U16TEXT);

    std::wcout << L"========== DLL Injector ==========" << std::endl;

    DWORD pid = 0;
    std::wcout << L"[?] Enter PID to inject into: ";
    std::wcin >> pid;

    if (pid == 0) {
        std::wcerr << L"[-] Invalid PID entered." << std::endl;
        std::wcout << L"[+] Press Enter to exit...";
        std::wcin.ignore();
        std::wcin.get();
        return 1;
    }

    PROCESSENTRY32 procInfo;
    if (!GetProcessInfoByPID(pid, procInfo)) {
        std::wcerr << L"[-] No process found with PID: " << pid << std::endl;
        std::wcout << L"[+] Press Enter to exit...";
        std::wcin.ignore();
        std::wcin.get();
        return 1;
    }

    std::wcout << L"[+] Process found!" << std::endl;
    std::wcout << L"    Name        : " << procInfo.szExeFile << std::endl;
    std::wcout << L"    PID         : " << procInfo.th32ProcessID << std::endl;
    std::wcout << L"    Threads     : " << procInfo.cntThreads << std::endl;
    std::wcout << L"    Parent PID  : " << procInfo.th32ParentProcessID << std::endl;

    std::wstring dllPath = L"C:\\Windows\\Temp\\WriteProcessMemory Hook.dll";

    if (!fs::exists(dllPath)) {
        std::wcerr << L"[-] DLL not found at: " << dllPath << std::endl;
        std::wcout << L"[+] Press Enter to exit...";
        std::wcin.ignore();
        std::wcin.get();
        return 1;
    }

    if (!InjectDLL(pid, dllPath)) {
        std::wcerr << L"[-] DLL injection failed." << std::endl;
    }
    else {
        std::wcout << L"[+] DLL successfully injected!" << std::endl;
    }

    std::wcout << L"[+] Press Enter to exit...";
    std::wcin.ignore();
    std::wcin.get();
    return 0;
}
