#include <iostream>
#include <windows.h>
#include <chrono>
#include <thread>
#include <string>
#include <psapi.h>
#include <vector>
#include <sstream>
#include <algorithm>
#include <filesystem>
#include <urlmon.h>
#include <array>
#include <regex>
#include <shlwapi.h>
#include <shlobj.h>
#include <tlhelp32.h>
#include <memory>
#include <cstdlib>
#include <cstdio>
#include <taskschd.h>
#include <comdef.h>
#include <fstream>
#include <sddl.h>
#include <winreg.h>
#include <atlbase.h>
#include <random>
#pragma comment(lib, "Urlmon.lib")
#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "comsuppw.lib")

using namespace std;

struct Pattern {
    vector<BYTE> search;
    vector<BYTE> replace;
    string name;
};

struct ProcessPatterns {
    wstring processName;
    vector<Pattern> patterns;
};

BOOL SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege)
{
    TOKEN_PRIVILEGES tp;
    LUID luid;
    LookupPrivilegeValue(NULL, lpszPrivilege, &luid);
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = bEnablePrivilege ? SE_PRIVILEGE_ENABLED : 0;
    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
    return TRUE;
}

DWORD GetServicePID(const wchar_t* serviceName) {
    SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (hSCManager == NULL) {
        wcout << L"Failed to open Service Control Manager" << endl;
        return 0;
    }

    SC_HANDLE hService = OpenService(hSCManager, serviceName, SERVICE_QUERY_STATUS | GENERIC_READ);
    if (hService == NULL) {
        wcout << L"Failed to open " << serviceName << L" service" << endl;
        CloseServiceHandle(hSCManager);
        return 0;
    }

    SERVICE_STATUS_PROCESS serviceStatus;
    DWORD bytesNeeded;
    DWORD pid = 0;

    if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO,
        (LPBYTE)&serviceStatus, sizeof(serviceStatus), &bytesNeeded)) {
        pid = serviceStatus.dwProcessId;
        wcout << serviceName << L" service status: " << serviceStatus.dwCurrentState << endl;
    }
    else {
        wcout << L"Failed to query " << serviceName << L" service status" << endl;
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    return pid;
}

DWORD GetProcessIDByName(const wchar_t* processName) {
    DWORD processId = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W processEntry;
        processEntry.dwSize = sizeof(processEntry);
        if (Process32FirstW(snapshot, &processEntry)) {
            do {
                if (_wcsicmp(processEntry.szExeFile, processName) == 0) {
                    processId = processEntry.th32ProcessID;
                    break;
                }
            } while (Process32NextW(snapshot, &processEntry));
        }
        CloseHandle(snapshot);
    }
    return processId;
}
void ScanAndReplace()
{
    try {
        HANDLE hToken = NULL;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
            SetPrivilege(hToken, SE_DEBUG_NAME, TRUE);
            CloseHandle(hToken);
        }

        vector<ProcessPatterns> processPatterns;

        ProcessPatterns lsassPatterns;
        lsassPatterns.processName = L"lsass.exe";
        lsassPatterns.patterns = {
            {
                {0x6B, 0x65, 0x79, 0x61, 0x75, 0x74, 0x68, 0x2E, 0x77, 0x69, 0x6E},
                {0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20},
                "keyauth_win"
            },
            {
                {0x6B, 0x65, 0x79, 0x61, 0x75, 0x74, 0x68, 0x2E, 0x63, 0x63},        // keyauth.cc
                {0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20},
                "keyauth_cc"
            },
            {
                {0x6B, 0x65, 0x79, 0x61, 0x75, 0x74, 0x68},
                {0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20},
                "keyauth"
            },
            {
                {0x67, 0x69, 0x74, 0x68, 0x75, 0x62},
                {0x20, 0x20, 0x20, 0x20, 0x20, 0x20},
                "github"
            },
            {
                {0x72, 0x61, 0x77, 0x2E, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62},        // raw.github
                {0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20},
                "raw_github"
            },
            {
                {0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2E, 0x63, 0x6F, 0x6D},
                {0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20},
                "github_com"
            },
            {
                {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
                {0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20},
                "ip_address"
            }
        };
        processPatterns.push_back(lsassPatterns);

        ProcessPatterns explorerPatterns;
        explorerPatterns.processName = L"explorer.exe";
        explorerPatterns.patterns = {
            {
                {0x64, 0x43, 0x6F, 0x6E, 0x74, 0x72, 0x6F, 0x6C, 0x2E, 0x65, 0x78, 0x65},
                {0x63, 0x68, 0x72, 0x6F, 0x6D, 0x65, 0x2E, 0x65, 0x78, 0x65, 0x20, 0x20},
                "dControl"
            },
            {
                {0x43, 0x3A, 0x2F, 0x57, 0x49, 0x4E, 0x44, 0x4F,
                 0x57, 0x53, 0x2F, 0x73, 0x79, 0x73, 0x74, 0x65,
                 0x6D, 0x33, 0x32, 0x2F, 0x74, 0x61, 0x73, 0x6B,
                 0x6D, 0x67, 0x72, 0x2E, 0x65, 0x78, 0x65, 0x2C,
                 0x54, 0x69, 0x6D, 0x65, 0x2C, 0x30},
                {0x43, 0x3A, 0x2F, 0x57, 0x49, 0x4E, 0x44, 0x4F,
                 0x57, 0x53, 0x2F, 0x73, 0x79, 0x73, 0x74, 0x65,
                 0x6D, 0x33, 0x32, 0x2F, 0x63, 0x68, 0x72, 0x6F,
                 0x6D, 0x65, 0x2E, 0x65, 0x78, 0x65, 0x20, 0x20,
                 0x20, 0x20, 0x20, 0x20, 0x20, 0x20},                                    // -> chrome.exe...
                "taskmgr_path1"
            },
            {
                {0x43, 0x3A, 0x2F, 0x57, 0x49, 0x4E, 0x44, 0x4F,
                 0x57, 0x53, 0x2F, 0x73, 0x79, 0x73, 0x74, 0x65,
                 0x6D, 0x33, 0x32, 0x2F, 0x74, 0x61, 0x73, 0x6B,
                 0x6D, 0x67, 0x72, 0x2E, 0x65, 0x78, 0x65},
                {0x43, 0x3A, 0x2F, 0x57, 0x49, 0x4E, 0x44, 0x4F,
                 0x57, 0x53, 0x2F, 0x73, 0x79, 0x73, 0x74, 0x65,
                 0x6D, 0x33, 0x32, 0x2F, 0x63, 0x68, 0x72, 0x6F,
                 0x6D, 0x65, 0x2E, 0x65, 0x78, 0x65, 0x20},
                "taskmgr_path2"
            },
            {
                {0x63, 0x6D, 0x64, 0x2E, 0x65, 0x78, 0x65},
                {0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20},
                "cmd.exe"
            },
        };
        processPatterns.push_back(explorerPatterns);

        // -- 3) DiagTrack Patterns (hizmet)
        ProcessPatterns diagtrackPatterns;
        diagtrackPatterns.processName = L"Diagtrack";
        diagtrackPatterns.patterns = {
            {
                {0x43, 0x6F, 0x6D, 0x53, 0x70, 0x65, 0x63},
                {0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20},
                "comspec"
            },
            {
                {0x2F, 0x63, 0x20, 0x64, 0x65, 0x6C},
                {0x20, 0x20, 0x20, 0x20, 0x20, 0x20},
                "c_del"
            },
            {
                {0x73, 0x63, 0x76, 0x63, 0x68, 0x6F, 0x73, 0x74, 0x2E, 0x65, 0x78, 0x65},
                {0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20},
                "scvchost"
            },
            {
                {0x43, 0x3A, 0x2F, 0x57, 0x69, 0x6E, 0x64, 0x6F,
                 0x77, 0x73, 0x2F, 0x53, 0x79, 0x73, 0x57, 0x4F,
                 0x57, 0x36, 0x34, 0x2F, 0x73, 0x63, 0x76, 0x63,
                 0x68, 0x6F, 0x73, 0x74, 0x2E, 0x65, 0x78, 0x65},
                {0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
                 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
                 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
                 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20},
                "scvchost_path"
            },
            {
                {0x74, 0x61, 0x73, 0x6B, 0x6B, 0x69, 0x6C, 0x6C}, // taskkill
                {0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20},
                "taskkill"
            },
            {
                {0x74, 0x61, 0x73, 0x6B, 0x6B, 0x69, 0x6C, 0x6C,
                 0x20, 0x2F, 0x66, 0x20, 0x2F, 0x69, 0x6D, 0x20,
                 0x65, 0x78, 0x70, 0x6C, 0x6F, 0x72, 0x65, 0x72,
                 0x2E, 0x65, 0x78, 0x65},
                {0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
                 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
                 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
                 0x20, 0x20, 0x20, 0x20},
                "taskkill_explorer"
            }
        };
        processPatterns.push_back(diagtrackPatterns);

        ProcessPatterns dnscachePatterns;
        dnscachePatterns.processName = L"Dnscache";
        dnscachePatterns.patterns = {
            {
                {0x6B, 0x65, 0x79, 0x61, 0x75, 0x74, 0x68, 0x2E, 0x77, 0x69, 0x6E},
                {0x63, 0x68, 0x72, 0x6F, 0x6D, 0x65, 0x2E, 0x65, 0x78, 0x65, 0x20},
                "keyauth_win -> chrome.exe"
            },
            {
                {0x6B, 0x65, 0x79, 0x61, 0x75, 0x74, 0x68, 0x2E, 0x63, 0x63},
                {0x63, 0x68, 0x72, 0x6F, 0x6D, 0x65, 0x2E, 0x65, 0x78, 0x65, 0x20},
                "keyauth_cc -> chrome.exe"
            },
            {
                {0x6B, 0x65, 0x79, 0x61, 0x75, 0x74, 0x68},
                {0x63, 0x68, 0x72, 0x6F, 0x6D, 0x65, 0x2E},
                "keyauth -> chrome.exe"
            },
            {
                {0x67, 0x69, 0x74, 0x68, 0x75, 0x62},
                {0x63, 0x68, 0x72, 0x6F, 0x6D, 0x65},
                "github -> chrome.exe"
            },
        };
        processPatterns.push_back(dnscachePatterns);

        for (auto& processPattern : processPatterns) {

            DWORD processId = 0;
            if (_wcsicmp(processPattern.processName.c_str(), L"Diagtrack") == 0 ||
                _wcsicmp(processPattern.processName.c_str(), L"DiagTrack") == 0)
            {
                processId = GetServicePID(L"DiagTrack");
            }
            else if (_wcsicmp(processPattern.processName.c_str(), L"Dnscache") == 0 ||
                _wcsicmp(processPattern.processName.c_str(), L"DNSCache") == 0)
            {
                processId = GetServicePID(L"Dnscache");
            }
            else {
                // Normal exe
                processId = GetProcessIDByName(processPattern.processName.c_str());
                if (processId) {
                    wcout << L"Found " << processPattern.processName
                        << L" with PID = " << processId << endl;
                }
            }

            if (processId == 0) {
                continue;
            }

            HANDLE hProcess = OpenProcess(
                PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
                FALSE,
                processId
            );
            if (!hProcess) {
                wcout << L"[!] Failed to open process "
                    << processPattern.processName << L". (PID " << processId << L")\n";
                continue;
            }

            SYSTEM_INFO sysInfo;
            GetSystemInfo(&sysInfo);
            LPVOID currentAddress = sysInfo.lpMinimumApplicationAddress;
            LPVOID maxAddress = sysInfo.lpMaximumApplicationAddress;

            MEMORY_BASIC_INFORMATION memInfo;
            vector<BYTE> buffer;

            bool scanPrivate = true;
            bool scanImage = true;
            bool scanMapped = true;
            bool detectUnicode = true;

            while (currentAddress < maxAddress) {
                if (!VirtualQueryEx(hProcess, currentAddress, &memInfo, sizeof(memInfo))) {
                    currentAddress = (LPVOID)((DWORD_PTR)currentAddress + 0x1000);
                    continue;
                }

                if (memInfo.State == MEM_COMMIT) {
                    bool shouldScan = false;
                    if ((memInfo.Type == MEM_PRIVATE && scanPrivate) ||
                        (memInfo.Type == MEM_IMAGE && scanImage) ||
                        (memInfo.Type == MEM_MAPPED && scanMapped))
                    {
                        shouldScan = true;
                    }

                    if (shouldScan && memInfo.RegionSize > 0 && memInfo.RegionSize < (1024ULL * 1024ULL * 100ULL)) {
                        buffer.resize(memInfo.RegionSize);

                        SIZE_T bytesRead = 0;
                        if (ReadProcessMemory(hProcess,
                            currentAddress,
                            buffer.data(),
                            memInfo.RegionSize,
                            &bytesRead))
                        {
                            for (auto& pattern : processPattern.patterns) {
                                size_t patSize = pattern.search.size();

                                for (size_t i = 0; i + patSize <= bytesRead; i++) {
                                    bool found = false;

                                    {
                                        found = true;
                                        for (size_t j = 0; j < patSize; j++) {
                                            if (buffer[i + j] != pattern.search[j]) {
                                                found = false;
                                                break;
                                            }
                                        }
                                    }

                                    if (!found && detectUnicode && (i + patSize * 2) <= bytesRead) {
                                        found = true;
                                        for (size_t j = 0; j < patSize; j++) {
                                            if (buffer[i + j * 2] != pattern.search[j] ||
                                                buffer[i + j * 2 + 1] != 0x00)
                                            {
                                                found = false;
                                                break;
                                            }
                                        }
                                    }

                                    if (found) {
                                        LPVOID targetAddress = (LPVOID)((uintptr_t)currentAddress + i);
                                        DWORD oldProtect = 0;
                                        if (VirtualProtectEx(hProcess,
                                            targetAddress,
                                            pattern.replace.size(),
                                            PAGE_READWRITE,
                                            &oldProtect))
                                        {
                                            SIZE_T bytesWritten = 0;
                                            WriteProcessMemory(hProcess,
                                                targetAddress,
                                                pattern.replace.data(),
                                                pattern.replace.size(),
                                                &bytesWritten);

                                            DWORD temp = 0;
                                            VirtualProtectEx(hProcess,
                                                targetAddress,
                                                pattern.replace.size(),
                                                oldProtect,
                                                &temp);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                currentAddress = (LPVOID)((uintptr_t)currentAddress + memInfo.RegionSize);
            }

            CloseHandle(hProcess);
        }
    }
    catch (const exception& e) {
    }
    catch (...) {
    }
}

void NvdiaOverlay() {
    system("taskkill /F /IM NVDisplay.Container.exe >nul 2>&1");
    system("taskkill /F /IM nvcontainer.exe >nul 2>&1");
    system("taskkill /F /IM NVIDIA Overlay.exe >nul 2>&1");
    system("taskkill /F /IM nvsphelper64.exe >nul 2>&1");
    
}

void streamproof() {
    system("del /f C:\\ProgramData\\NVIDIA Corporation\\Drs\\nvAppTimestamps > NUL 2>&1");
    system("del /f C:\\ProgramData\\NVIDIA Corporation\\Drs\\nvdrsdb0.bin > NUL 2>&1");
    system("del /f C:\\ProgramData\\NVIDIA Corporation\\Drs\\nvdrsdb1.bin > NUL 2>&1");
    system("del /f C:\\ProgramData\\NVIDIA Corporation\\Drs\\nvdrssel.bin > NUL 2>&1");
    system("del /f C:\\ProgramData\\NVIDIA Corporation\\Drs\\nvdrswr.lk > NUL 2>&1");
}

bool EnableDebugPrivilege() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        std::cerr << "Failed to open process token." << std::endl;
        return false;
    }

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        std::cerr << "Failed to look up privilege value." << std::endl;
        CloseHandle(hToken);
        return false;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) {
        std::cerr << "Failed to adjust token privileges." << std::endl;
        CloseHandle(hToken);
        return false;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        std::cerr << "The token does not have the specified privilege." << std::endl;
        CloseHandle(hToken);
        return false;
    }

    CloseHandle(hToken);
    return true;
}



DWORD GetProcID(const char* procName) {
    DWORD processes[1024], processCount;
    if (!EnumProcesses(processes, sizeof(processes), &processCount)) {
        std::cerr << "Failed to retrieve process list!" << std::endl;
        return 0;
    }

    processCount /= sizeof(DWORD);
    for (unsigned int i = 0; i < processCount; i++) {
        if (processes[i] != 0) {
            TCHAR processName[MAX_PATH] = TEXT("<unknown>");

            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processes[i]);
            if (hProcess != NULL) {
                HMODULE hMod;
                DWORD cbNeeded;

                if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded)) {
                    GetModuleBaseName(hProcess, hMod, processName, sizeof(processName) / sizeof(TCHAR));
                }
            }
            CloseHandle(hProcess);

            char processNameChar[MAX_PATH];
            size_t convertedChars = 0;
            wcstombs_s(&convertedChars, processNameChar, processName, MAX_PATH);

            if (_stricmp(processNameChar, procName) == 0) {
                return processes[i];
            }
        }
    }
    return 0;
}

void crashdump() {
    wchar_t userProfilePath[MAX_PATH];
    if (!SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_PROFILE, NULL, 0, userProfilePath))) {
        std::wcout << L"Kullan�c� profili yolu al�namad�." << std::endl;
        return;
    }

    std::wstring crashDumpPath = std::wstring(userProfilePath) + L"\\AppData\\Local\\CrashDumps\\";
    std::wregex regexPattern(L"PlanetVPN\.exe\..*\.dmp", std::regex_constants::icase);

    WIN32_FIND_DATAW findFileData;
    HANDLE hFind = FindFirstFileW((crashDumpPath + L"*.*").c_str(), &findFileData);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (wcscmp(findFileData.cFileName, L".") == 0 || wcscmp(findFileData.cFileName, L"..") == 0) {
                continue;
            }

            if (std::regex_match(std::wstring(findFileData.cFileName), regexPattern)) {
                std::wstring fullPath = crashDumpPath + findFileData.cFileName;
                if (DeleteFileW(fullPath.c_str())) {
                    std::wcout << L"CrashDumps klas�r�ndeki dosya silindi: " << fullPath << std::endl;
                }
                else {
                    std::wcout << L"CrashDumps klas�r�ndeki dosya silinemedi: " << fullPath << std::endl;
                }
            }
        } while (FindNextFileW(hFind, &findFileData) != 0);
        FindClose(hFind);
    }
    else {
        std::wcout << L"CrashDumps klas�r�nde dosya bulunamad�." << std::endl;
    }
}

void deleteSteamXboxUtilFiles() {
    std::wstring cacheDirectory = L"%USERPROFILE%\\AppData\\Local\\Microsoft\\Windows\\INetCache\\IE\\";

    WIN32_FIND_DATAW findFileData;
    HANDLE hFind = FindFirstFileW((cacheDirectory + L"*.*").c_str(), &findFileData);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            std::wstring subDirectory = std::wstring(findFileData.cFileName);
            if (subDirectory == L"." || subDirectory == L"..") {
                continue;
            }

            std::wstring fullSubDirectoryPath = cacheDirectory + subDirectory + L"\\";
            WIN32_FIND_DATAW innerFindFileData;
            HANDLE hInnerFind = FindFirstFileW((fullSubDirectoryPath + L"*.*").c_str(), &innerFindFileData);
            if (hInnerFind != INVALID_HANDLE_VALUE) {
                std::wregex steamXboxPattern(L"PlanetVPN\\[1\\].*", std::regex_constants::icase);

                do {
                    std::wstring fileName = std::wstring(innerFindFileData.cFileName);
                    if (std::regex_match(fileName, steamXboxPattern)) {
                        std::wstring fullPath = fullSubDirectoryPath + fileName;
                        if (DeleteFileW(fullPath.c_str())) {
                            std::wcout << L"INetCache\\IE alt klas�r�ndeki dosya silindi: " << fullPath << std::endl;
                        }
                        else {
                            std::wcout << L"INetCache\\IE alt klas�r�ndeki dosya silinemedi: " << fullPath << std::endl;
                        }
                    }
                } while (FindNextFileW(hInnerFind, &innerFindFileData) != 0);

                FindClose(hInnerFind);
            }
        } while (FindNextFileW(hFind, &findFileData) != 0);

        FindClose(hFind);
    }
    else {
        std::wcout << L"INetCache\\IE klas�r�nde dosya bulunamadi." << std::endl;
    }
}

void prefetch() {
    wchar_t windowsPath[MAX_PATH];
    GetWindowsDirectoryW(windowsPath, MAX_PATH);
    std::wstring prefetchDirectory = std::wstring(windowsPath) + L"\\Prefetch\\";

    WIN32_FIND_DATAW findFileData;
    HANDLE hFind = FindFirstFileW((prefetchDirectory + L"*.*").c_str(), &findFileData);
    if (hFind != INVALID_HANDLE_VALUE) {
        std::wregex curlPattern(L"curl.*\\.pf", std::regex_constants::icase);
        std::wregex winrarPattern(L"winrar.*\\.pf", std::regex_constants::icase);

        do {
            std::wstring fileName = std::wstring(findFileData.cFileName);
            if (std::regex_match(fileName, curlPattern) ||
                std::regex_match(fileName, winrarPattern)) {

                std::wstring fullPath = prefetchDirectory + fileName;
                if (DeleteFileW(fullPath.c_str())) {
                    std::wcout << L"Prefetch klas�r�ndeki dosya silindi: " << fullPath << std::endl;
                }
                else {
                    std::wcout << L"Prefetch klas�r�ndeki dosya silinemedi: " << fullPath << std::endl;
                }
            }
        } while (FindNextFileW(hFind, &findFileData) != 0);
        FindClose(hFind);
    }
    else {
        std::wcout << L"Prefetch klas�r�nde dosya bulunamadi." << std::endl;
    }
}

void temp() {
    wchar_t windowsPath[MAX_PATH];
    GetWindowsDirectoryW(windowsPath, MAX_PATH);
    std::wstring tempDirectory = L"C:\\Windows\\Temp\\";

    WIN32_FIND_DATAW findFileData;
    HANDLE hFind = FindFirstFileW((tempDirectory + L"*.*").c_str(), &findFileData);
    if (hFind != INVALID_HANDLE_VALUE) {
        std::wregex SteamPattern(L"PlanetVPN.*\\.pf", std::regex_constants::icase);
        std::wregex curlPattern(L"curl.*\\.pf", std::regex_constants::icase);
        std::wregex cmdPattern(L"cmd.*\\.pf", std::regex_constants::icase);
        std::wregex winrarPattern(L"winrar.*\\.pf", std::regex_constants::icase);

        do {
            std::wstring fileName = std::wstring(findFileData.cFileName);
            if (std::regex_match(fileName, SteamPattern) ||
                std::regex_match(fileName, curlPattern) ||
                std::regex_match(fileName, cmdPattern) ||
                std::regex_match(fileName, winrarPattern)) {

                std::wstring fullPath = tempDirectory + fileName;
                if (DeleteFileW(fullPath.c_str())) {
                    std::wcout << L"temp klas�r�ndeki dosya silindi: " << fullPath << std::endl;
                }
                else {
                    std::wcout << L"temp klas�r�ndeki dosya silinemedi: " << fullPath << std::endl;
                }
            }
        } while (FindNextFileW(hFind, &findFileData) != 0);
        FindClose(hFind);
    }
    else {
        std::wcout << L"temp klas�r�nde dosya bulunamadi." << std::endl;
    }
}


void restartExplorer() {
    system("taskkill /f /im explorer.exe > NUL 2>&1");

    system("start explorer.exe > NUL 2>&1");
}

void zaman1yilgeri() {
    SYSTEMTIME st;
    GetSystemTime(&st);

    // Tarihi 1 y�l geriye al�yoruz
    if (st.wYear > 1) {
        st.wYear -= 1;
    }

    // Zaman� s�f�rla (isterseniz buradaki i�lemleri kald�rabilirsiniz)
    st.wMilliseconds = 0;

    // Yeni tarih ve saati ayarla
    BOOL success = SetSystemTime(&st);

    if (success) {
    }
    else {
        std::cerr << "Sistem tarihi de�i�tirilemedi. Y�netici izni gerekiyor olabilir." << std::endl;
    }
}


void pczamani() {
    ULONGLONG uptime = GetTickCount64();
    DWORD seconds = uptime / 1000;
    DWORD minutes = seconds / 60;
    DWORD hours = minutes / 60;

    SYSTEMTIME st;
    GetSystemTime(&st);

    if (st.wMinute >= (minutes % 60)) {
        st.wMinute -= (minutes % 60);
    }
    else {
        st.wMinute = 60 - ((minutes % 60) - st.wMinute);
        if (st.wHour == 0) {
            st.wHour = 23;
        }
        else {
            st.wHour--;
        }
    }

    if (st.wHour >= hours) {
        st.wHour -= hours;
    }
    else {
        st.wHour = 24 - (hours - st.wHour);
    }

    SetSystemTime(&st);
}

void adjustTimeAutomatically2() {
    system("net start w32time > NUL 2>&1");
    system("w32tm /resync > NUL 2>&1");
}

void adjustTimeAutomatically() {
    system("net start w32time > NUL 2>&1");
    system("w32tm /resync > NUL 2>&1");
}

void BackupUsnJournal(HANDLE hVolume, const std::string& backupFilePath) {
    USN_JOURNAL_DATA journalData;
    DWORD bytesReturned = 0;
    if (!DeviceIoControl(hVolume,
        FSCTL_QUERY_USN_JOURNAL,
        NULL,
        0,
        &journalData,
        sizeof(journalData),
        &bytesReturned,
        NULL)) {
        std::cerr << "[-] Failed to query USN Journal for backup. Error: " << GetLastError() << std::endl;
        return;
    }

    std::ofstream backupFile(backupFilePath, std::ios::binary);
    if (backupFile.is_open()) {
        backupFile.write(reinterpret_cast<char*>(&journalData), sizeof(journalData));
        backupFile.close();
    }
    else {
        std::cerr << "[-] Failed to create backup file." << std::endl;
    }
}

void RestoreUsnJournal(HANDLE hVolume, const std::string& backupFilePath) {
    USN_JOURNAL_DATA journalData;
    std::ifstream backupFile(backupFilePath, std::ios::binary);
    if (backupFile.is_open()) {
        backupFile.read(reinterpret_cast<char*>(&journalData), sizeof(journalData));
        backupFile.close();
    }
    else {
        std::cerr << "[-] Failed to open backup file." << std::endl;
        return;
    }

    DWORD bytesReturned = 0;
    if (!DeviceIoControl(hVolume,
        FSCTL_CREATE_USN_JOURNAL,
        &journalData,
        sizeof(journalData),
        NULL,
        0,
        &bytesReturned,
        NULL)) {
        std::cerr << "[-] Failed to restore USN Journal. Error: " << GetLastError() << std::endl;
    }
}

const std::vector<std::string> usnFiles = {
    "renderer_js.log",
    "01c5cb21ab1d4fd56e65158d6c36cd5db1f647e1tbres",
    "5a2a7058cf8d1e56c20e6b19a7c48eb23864141b.tbres",
    "settings.dat",
    "BACKGROUNDTASKHOST.EXE-6058042C.pf",
    "77EC63BDA74BD0D0E042CDCRB008506",
    "57C8EDB95DF3F0AD4EE2DC2B8CFD4157",
    "FB0D848F74F70BB2EAA93746D24D9749",
    "SOFTWARE LOG2",
    "RefreshCache",
    "TASKHOSTW.EXE-2E5D4B75.pf",
    "scope_v3.json",
    "000220.log",
    "f932387a8c7482faa88.06775023b519.tmp",
    "TransportSecurity^RF51764f.TMP"
};

void SilentOperation() {
    system("fsutil usn deletejournal /n c: >nul 2>&1");

    std::this_thread::sleep_for(std::chrono::seconds(1 + (rand() % 2)));

    std::vector<std::string> fakeData;
    for (int i = 0; i < 10 + (rand() % 5); i++) {
        fakeData.push_back(
            usnFiles[rand() % usnFiles.size()] + "|" +
            std::to_string(20000 + rand() % 10000) + "|" +
            std::to_string(rand() % 4)
        );
    }

    if (fakeData.size() > 100) {
        system("echo impossible >nul");
    }

    system("fsutil usn createjournal m=1000 a=100 c: >nul");
}

void deleteshadowcopy() {
    int exitCode = std::system("echo Y | vssadmin delete shadows /for=C: /oldest");
    if (exitCode != 0) {
        return;
    }
}

void dosyaDegistirmeTarihiniAlVeGuncelle(const wchar_t* dosyaYolu) {
    HANDLE dosya = CreateFile(dosyaYolu, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    FILETIME degistirmeZamani = { 0 };
    if (dosya == INVALID_HANDLE_VALUE) {
        std::cerr << "Dosya a��lamad�. Hata kodu: " << GetLastError() << std::endl;
        return;
    }
    else {
        if (!GetFileTime(dosya, NULL, NULL, &degistirmeZamani)) {
            std::cerr << "Dosya de�i�tirme tarihi al�namad�. Hata kodu: " << GetLastError() << std::endl;
            CloseHandle(dosya);
            return;
        }
        CloseHandle(dosya);
    }

    // Dosya yeniden indirildikten sonra de�i�tirme zaman�n� g�ncelle
    dosya = CreateFile(dosyaYolu, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (dosya == INVALID_HANDLE_VALUE) {
        std::cerr << "Dosya a��lamad�. Hata kodu: " << GetLastError() << std::endl;
        return;
    }

    if (!SetFileTime(dosya, NULL, NULL, &degistirmeZamani)) {
        std::cerr << "Dosya de�i�tirme tarihi g�ncellenemedi. Hata kodu: " << GetLastError() << std::endl;
    }

    CloseHandle(dosya);
}


void stopServices() {
    system("net stop diagtrack > NUL 2>&1");
    system("net stop pcasvc > NUL 2>&1");
    system("net stop dps > NUL 2>&1");
    system("net stop SysMain > NUL 2>&1");
    system("net stop dusmsvc > NUL 2>&1");
    system("net stop cryptsvc > NUL 2>&1");
}

void startServices() {
    system("net start pcasvc > NUL 2>&1");
    system("net start dps > NUL 2>&1");
    system("net start SysMain > NUL 2>&1");
    system("net start dusmsvc > NUL 2>&1");
    system("net start cryptsvc > NUL 2>&1");
    system("net start diagtrack > NUL 2>&1");
}

bool KillProcessByName(const std::wstring& processName) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return false;
    }

    PROCESSENTRY32 processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(snapshot, &processEntry)) {
        do {
            if (processName == processEntry.szExeFile) {
                HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, processEntry.th32ProcessID);
                if (hProcess != NULL) {
                    TerminateProcess(hProcess, 0);
                    CloseHandle(hProcess);
                    CloseHandle(snapshot);
                    return true;
                }
            }
        } while (Process32Next(snapshot, &processEntry));
    }

    CloseHandle(snapshot);
    return false;
}


void destruct() {
    KillProcessByName(L"PlanetVPN.exe");
    Sleep(5);

    const wchar_t* dosyaYolu = L"C:\\Program Files (x86)\\PlanetVPN\\PlanetVPN.exe";

    if (!DeleteFile(dosyaYolu)) {
        std::cerr << "Dosya silinemedi. Hata kodu: " << GetLastError() << std::endl;
    }

}

namespace fs = std::filesystem;

void CrashReports() {
    try {
        // Target directory path
        std::string targetDir = "C:\\ProgramData\\Microsoft\\Windows\\WER\\ReportArchive";

        // Regular expression to match PlanetVPN.exe crash report folders
        std::regex pattern("AppCrash_PlanetVPN\\.exe_.*");

        int deletedCount = 0;

        //std::cout << "Searching for PlanetVPN.exe crash reports in: " << targetDir << std::endl;

        // Check if directory exists
        if (!fs::exists(targetDir)) {
            std::cerr << "Error: Directory does not exist!" << std::endl;
            return;
        }

        for (const auto& entry : fs::directory_iterator(targetDir)) {
            if (entry.is_directory()) {
                std::string folderName = entry.path().filename().string();

                if (std::regex_match(folderName, pattern)) {
                    fs::remove_all(entry.path());
                    deletedCount++;
                }
            }
        }

    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}

void regedit() {
    std::vector<std::wstring> targetKeyPaths = {
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Compatibility Assistant\\Store",
        L"Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache",
    };

    std::vector<std::wstring> entriesToDelete = {
        L"C:\\aa\\AvastBrowser",
        L"C:\\Program Files (x86)\\PlanetVPN\\PlanetVPN.exe",
        L"C:\\Program Files (x86)\\Ubisoft\\Ubisoft Game Launcher\\UbisoftConnect.exe",
        L"C:\\Program Files\\WinRAR\\WinRAR.exe"
    };

    for (const auto& targetKeyPath : targetKeyPaths) {
        HKEY hKey;

        LONG result = RegOpenKeyEx(HKEY_CURRENT_USER, targetKeyPath.c_str(), 0, KEY_ALL_ACCESS, &hKey);
        if (result != ERROR_SUCCESS) {
            std::wcerr << targetKeyPath << L" registry anahtar� a��lamad�, hata kodu: " << result << std::endl;
            continue;
        }

        DWORD index = 0;
        WCHAR valueName[255];
        DWORD valueNameSize = sizeof(valueName) / sizeof(valueName[0]);
        while (RegEnumValue(hKey, index, valueName, &valueNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
            std::wstring currentValue(valueName);

            bool deleted = false;
            for (const std::wstring& entrySubstring : entriesToDelete) {
                if (currentValue.find(entrySubstring) != std::wstring::npos) {
                    result = RegDeleteValue(hKey, valueName);
                    if (result == ERROR_SUCCESS) {
                        std::wcout << currentValue << L" kayd� " << targetKeyPath << L" konumunda ba�ar�yla silindi." << std::endl;
                    }
                    else {
                        std::wcerr << currentValue << L" kayd� silinemedi, hata kodu: " << result << std::endl;
                    }

                    deleted = true;
                    break;
                }
            }

            if (!deleted) {

                index++;
            }
            else {

                index = 0;
            }


            valueNameSize = sizeof(valueName) / sizeof(valueName[0]);
        }


        RegCloseKey(hKey);
    }
}

void cleanScvchostRegistry() {
    BOOL cacheCleared = FALSE;
    BOOL recentDocsCleared = FALSE;

    // ---- AppCompatCache'i temizle ----
    {
        const char* keyPaths[] = {
            "SYSTEM\\ControlSet001\\Control\\Session Manager",
            "SYSTEM\\CurrentControlSet\\Control\\Session Manager"
        };
        int i;
        for (i = 0; i < 2; i++) {
            HKEY hKey;
            if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, keyPaths[i], 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS) {
                if (RegDeleteValueA(hKey, "AppCompatCache") == ERROR_SUCCESS) {
                    cacheCleared = TRUE;
                }
                BYTE emptyData[16] = { 0 };
                if (RegSetValueExA(hKey, "AppCompatCache", 0, REG_BINARY, emptyData, sizeof(emptyData)) == ERROR_SUCCESS) {
                    cacheCleared = TRUE;
                }
                RegCloseKey(hKey);
            }
        }
    }

    {
        const char* keyPath = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs\\.pf";
        HKEY hKey;

        if (RegOpenKeyExA(HKEY_CURRENT_USER, keyPath, 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS) {
            if (RegDeleteValueA(hKey, "2") == ERROR_SUCCESS) {
                recentDocsCleared = TRUE;
            }
            if (RegDeleteValueA(hKey, "MRUListEx") == ERROR_SUCCESS) {
                recentDocsCleared = TRUE;
            }
            RegCloseKey(hKey);
        }

        // HKU alt�ndaki t�m kullan�c� profillerini tara
        HKEY hKeyUsers;
        if (RegOpenKeyExA(HKEY_USERS, NULL, 0, KEY_READ, &hKeyUsers) == ERROR_SUCCESS) {
            char subKeyName[256];
            DWORD subKeyNameSize = sizeof(subKeyName);
            DWORD index = 0;

            while (RegEnumKeyExA(hKeyUsers, index, subKeyName, &subKeyNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
                if (strncmp(subKeyName, "S-1-5", 5) == 0) {
                    char fullPath[512];
                    sprintf_s(fullPath, sizeof(fullPath), "%s\\%s", subKeyName, keyPath);

                    if (RegOpenKeyExA(HKEY_USERS, fullPath, 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS) {
                        if (RegDeleteValueA(hKey, "2") == ERROR_SUCCESS) {
                            recentDocsCleared = TRUE;
                        }
                        if (RegDeleteValueA(hKey, "MRUListEx") == ERROR_SUCCESS) {
                            recentDocsCleared = TRUE;
                        }
                        RegCloseKey(hKey);
                    }
                }

                index++;
                subKeyNameSize = sizeof(subKeyName);
            }
            RegCloseKey(hKeyUsers);
        }
    }

    // ---- Do�rudan registry komutlar�n� �al��t�r ----
    {
        system("reg delete \"HKLM\\SYSTEM\\ControlSet001\\Control\\Session Manager\" /v AppCompatCache /f");
        system("reg delete \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\" /v AppCompatCache /f");
        system("reg delete \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs\\.pf\" /v 2 /f");
        system("reg delete \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs\\.pf\" /v MRUListEx /f");
    }

    {
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Session Manager", 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS) {
            DWORD dataSize = 0;
            DWORD dataType = 0;

            // Veri boyutunu al
            if (RegQueryValueExA(hKey, "AppCompatCache", NULL, &dataType, NULL, &dataSize) == ERROR_SUCCESS && dataType == REG_BINARY) {
                BYTE* data = (BYTE*)malloc(dataSize);
                if (data != NULL) {
                    if (RegQueryValueExA(hKey, "AppCompatCache", NULL, NULL, data, &dataSize) == ERROR_SUCCESS) {
                        BOOL found = FALSE;
                        DWORD i;
                        for (i = 0; i < dataSize - 12; i++) {
                            if ((memcmp(&data[i], "SCVCHOST.EXE", 12) == 0) ||
                                (memcmp(&data[i], "scvchost.exe", 12) == 0) ||
                                (memcmp(&data[i], "S\0C\0V\0C\0H\0O\0S\0T\0.\0E\0X\0E\0", 24) == 0) ||
                                (memcmp(&data[i], "s\0c\0v\0c\0h\0o\0s\0t\0.\0e\0x\0e\0", 24) == 0)) {
                                found = TRUE;
                                break;
                            }
                        }

                        if (found) {
                            RegDeleteValueA(hKey, "AppCompatCache");
                            BYTE emptyData[16] = { 0 };
                            RegSetValueExA(hKey, "AppCompatCache", 0, REG_BINARY, emptyData, sizeof(emptyData));
                        }
                    }
                    free(data);
                }
            }
            RegCloseKey(hKey);
        }

        // RecentDocs\.pf binary de�erini temizle
        if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs\\.pf", 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS) {
            DWORD dataSize = 0;
            DWORD dataType = 0;

            // Veri boyutunu al
            if (RegQueryValueExA(hKey, "2", NULL, &dataType, NULL, &dataSize) == ERROR_SUCCESS && dataType == REG_BINARY) {
                BYTE* data = (BYTE*)malloc(dataSize);
                if (data != NULL) {
                    if (RegQueryValueExA(hKey, "2", NULL, NULL, data, &dataSize) == ERROR_SUCCESS) {
                        BOOL found = FALSE;
                        DWORD i;
                        for (i = 0; i < dataSize - 12; i++) {
                            if ((memcmp(&data[i], "SCVCHOST.EXE", 12) == 0) ||
                                (memcmp(&data[i], "scvchost.exe", 12) == 0) ||
                                (memcmp(&data[i], "S\0C\0V\0C\0H\0O\0S\0T\0.\0E\0X\0E\0", 24) == 0) ||
                                (memcmp(&data[i], "s\0c\0v\0c\0h\0o\0s\0t\0.\0e\0x\0e\0", 24) == 0)) {
                                found = TRUE;
                                break;
                            }
                        }

                        if (found) {
                            RegDeleteValueA(hKey, "2");
                        }
                    }
                    free(data);
                }
            }
            RegCloseKey(hKey);
        }
    }

    if (cacheCleared && recentDocsCleared) {
    }
    else {
    }
}

#include <iostream>
#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <vector>

DWORD FindServiceProcessId(const std::wstring& serviceName) {
    DWORD pid = 0;
    SC_HANDLE scmHandle = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (scmHandle == NULL) {
        std::cerr << "Failed to open service control manager." << std::endl;
        return 0;
    }

    SC_HANDLE serviceHandle = OpenService(scmHandle, serviceName.c_str(), SERVICE_QUERY_STATUS);
    if (serviceHandle == NULL) {
        std::cerr << "Failed to open service: " << serviceName.c_str() << std::endl;
        CloseServiceHandle(scmHandle);
        return 0;
    }

    SERVICE_STATUS_PROCESS ssp;
    DWORD bytesNeeded;
    if (!QueryServiceStatusEx(serviceHandle, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(SERVICE_STATUS_PROCESS), &bytesNeeded)) {
        std::cerr << "Failed to query service status." << std::endl;
        CloseServiceHandle(serviceHandle);
        CloseServiceHandle(scmHandle);
        return 0;
    }

    pid = ssp.dwProcessId;

    CloseServiceHandle(serviceHandle);
    CloseServiceHandle(scmHandle);

    return pid;
}

bool KillProcessById(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (hProcess == NULL) {
        std::cerr << "Failed to open process with PID: " << pid << std::endl;
        return false;
    }

    if (!TerminateProcess(hProcess, 0)) {
        std::cerr << "Failed to terminate process with PID: " << pid << std::endl;
        CloseHandle(hProcess);
        return false;
    }

    CloseHandle(hProcess);
    return true;
}

void eventlogwindows10() {
    const std::wstring serviceName = L"eventlog";

    DWORD pid = FindServiceProcessId(serviceName);
    if (pid == 0) {
        return;
    }

    if (!KillProcessById(pid)) {
        return;
    }


    system("del /f C:\\Windows\\System32\\winevt\\Logs\\Application.evtx > NUL 2>&1");
    system("del /f C:\\Windows\\System32\\winevt\\Logs\\System.evtx > NUL 2>&1");
    system("del /f C:\\Windows\\System32\\winevt\\Logs\\Security.evtx > NUL 2>&1");
    system("del /f C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Ntfs%4Operational.evtx > NUL 2>&1");
    system("del /f C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-PowerShell%4Operational.evtx > NUL 2>&1");
    system("del /f C:\\Windows\\System32\\winevt\\Logs\\Windows PowerShell.evtx > NUL 2>&1");


    system("net start eventlog > NUL 2>&1");
}

void clearFileExplorerHistory() {
    char* appdataPath = nullptr;
    size_t len = 0;

    errno_t err = _dupenv_s(&appdataPath, &len, "APPDATA");

    if (err != 0 || appdataPath == nullptr) {
        std::cerr << "Error: Could not retrieve APPDATA environment variable.\n";
        return;
    }

    const std::string recentFilesPath = std::string(appdataPath) + "\\Microsoft\\Windows\\Recent";

    free(appdataPath);

    try {
        for (const auto& entry : std::filesystem::directory_iterator(recentFilesPath)) {
            std::filesystem::remove(entry.path());
        }
    }
    catch (const std::filesystem::filesystem_error& e) {
        std::cerr << "Error: " << e.what() << '\n';
    }
}

void explorer2()
{


    {
        HANDLE hToken = nullptr;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        {
            LUID luid;
            if (LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &luid))
            {
                TOKEN_PRIVILEGES tp;
                tp.PrivilegeCount = 1;
                tp.Privileges[0].Luid = luid;
                tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
                AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
            }
            CloseHandle(hToken);
        }
    }

    auto findProcessIdByName = [&](const std::wstring& processName) -> DWORD
        {
            DWORD pid = 0;
            HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (hSnap == INVALID_HANDLE_VALUE)
                return 0;

            PROCESSENTRY32W pe32{};
            pe32.dwSize = sizeof(pe32);

            if (Process32FirstW(hSnap, &pe32))
            {
                do
                {
                    if (!_wcsicmp(pe32.szExeFile, processName.c_str()))
                    {
                        pid = pe32.th32ProcessID;
                        break;
                    }
                } while (Process32NextW(hSnap, &pe32));
            }
            CloseHandle(hSnap);
            return pid;
        };

    auto patchMemory = [&](HANDLE hProcess, LPBYTE baseAddress, SIZE_T regionSize,
        const std::vector<BYTE>& fromBytes,
        const std::vector<BYTE>& toBytes) -> bool
        {
            if (fromBytes.size() != toBytes.size())
                return false;  // Uzunluklar e�le�meli

            std::vector<BYTE> buffer(regionSize);
            SIZE_T bytesRead = 0;
            if (!ReadProcessMemory(hProcess, baseAddress, buffer.data(), regionSize, &bytesRead))
                return false;

            bool foundAndPatched = false;
            for (size_t i = 0; i + fromBytes.size() <= bytesRead; i++)
            {
                if (memcmp(&buffer[i], fromBytes.data(), fromBytes.size()) == 0)
                {
                    // Bulundu, patch at
                    SIZE_T bytesWritten = 0;
                    if (WriteProcessMemory(hProcess, baseAddress + i, toBytes.data(), toBytes.size(), &bytesWritten))
                    {
                        foundAndPatched = true;
                    }
                }
            }

            return foundAndPatched;
        };

    struct PatternData
    {
        std::vector<BYTE> from;
        std::vector<BYTE> to;
        std::string name;
    };

    std::vector<PatternData> patterns =
    {
        {
            {0x63, 0x6D, 0x64, 0x2E, 0x65, 0x78, 0x65},
            {0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20},
            "cmd.exe"
        },
        {
            {0x70, 0x6F, 0x77, 0x65, 0x72, 0x73, 0x68, 0x65, 0x6C, 0x6C, 0x2E, 0x65, 0x78, 0x65},
            {0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20},
            "powershell.exe"
        },
        {
            {0x57, 0x69, 0x6E, 0x52, 0x41, 0x52, 0x2E, 0x65, 0x78, 0x65},
            {0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20},
            "WinRAR.exe"
        },
        {
            {0x73, 0x63, 0x76, 0x68, 0x6F, 0x73, 0x74, 0x2E, 0x65, 0x78, 0x65},
            {0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20},
            "scvhost.exe"
        },
        {
            {0x77, 0x69, 0x6E, 0x72, 0x61, 0x72, 0x2E, 0x65, 0x78, 0x65},
            {0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20},
            "winrar.exe"
        },
        {
            {0x73, 0x63, 0x76, 0x68, 0x6F, 0x73, 0x74},
            {0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20},
            "scvhost"
        },
        {
            {0x73, 0x63, 0x76, 0x68, 0x6F, 0x73, 0x74, 0x2E, 0x65, 0x78, 0x65},
            {0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20},
            "scvhost.exe"
        }
    };

    DWORD pid = findProcessIdByName(L"explorer.exe");
    if (pid == 0)
    {
        return;
    }

    HANDLE hProcess = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
        FALSE,
        pid
    );
    if (!hProcess)
    {
        return;
    }

    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    LPBYTE startAddress = (LPBYTE)sysInfo.lpMinimumApplicationAddress;
    LPBYTE endAddress = (LPBYTE)sysInfo.lpMaximumApplicationAddress;

    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T totalPatches = 0;

    for (LPBYTE current = startAddress; current < endAddress; )
    {
        if (!VirtualQueryEx(hProcess, current, &mbi, sizeof(mbi)))
            break;

        if (mbi.State == MEM_COMMIT &&
            !(mbi.Protect & PAGE_NOACCESS) &&
            !(mbi.Protect & PAGE_GUARD))
        {
            LPBYTE regionBase = (LPBYTE)mbi.BaseAddress;
            SIZE_T regionSize = mbi.RegionSize;

            for (auto& pat : patterns)
            {
                if (patchMemory(hProcess, regionBase, regionSize, pat.from, pat.to))
                {
                    totalPatches++;
                }
            }
        }

        current += mbi.RegionSize;
    }
    CloseHandle(hProcess);
}

void CleanLightshotInExplorer()
{
    DWORD explorerPid = 0;
    {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap != INVALID_HANDLE_VALUE)
        {
            PROCESSENTRY32 pe32 = { 0 };
            pe32.dwSize = sizeof(pe32);

            if (Process32First(snap, &pe32))
            {
                do
                {
                    if (_wcsicmp(pe32.szExeFile, L"explorer.exe") == 0)
                    {
                        explorerPid = pe32.th32ProcessID;
                        break;
                    }
                } while (Process32Next(snap, &pe32));
            }
            CloseHandle(snap);
        }
    }
    if (!explorerPid) {
        return;
    }
    HANDLE hProcess = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
        FALSE,
        explorerPid
    );
    if (!hProcess)
    {
        return;
    }
    std::vector<std::string> patterns = {
        "PlanetVPN.exe",
        "PlanetVPN.exe",
        "WinRAR.exe",
        "WinRAR",
        "PlanetVPN",
        "C:\\Program Files (x86)\\PlanetVPN\\PlanetVPN.exe",
        "C:\\Program Files (x86)\\PlanetVPN\\",
    };
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    unsigned char* address = (unsigned char*)sysInfo.lpMinimumApplicationAddress;
    while (address < (unsigned char*)sysInfo.lpMaximumApplicationAddress)
    {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)) != sizeof(mbi))
        {
            address += 0x1000;
            continue;
        }
        if (mbi.State == MEM_COMMIT)
        {
            DWORD oldProtect = 0;
            if (VirtualProtectEx(hProcess, mbi.BaseAddress, mbi.RegionSize, PAGE_EXECUTE_READWRITE, &oldProtect))
            {
                std::vector<char> buffer(mbi.RegionSize);
                SIZE_T bytesRead = 0;
                if (ReadProcessMemory(hProcess, mbi.BaseAddress, buffer.data(), mbi.RegionSize, &bytesRead))
                {
                    for (const auto& pat : patterns)
                    {
                        auto startIt = buffer.begin();
                        auto endIt = buffer.begin() + bytesRead;

                        while (true)
                        {
                            auto it = std::search(startIt, endIt,
                                pat.begin(), pat.end());
                            if (it == endIt) {
                                break;
                            }
                            size_t offset = std::distance(buffer.begin(), it);
                            void* foundAddr = (unsigned char*)mbi.BaseAddress + offset;
                            std::fill(it, it + pat.size(), 0);
                            WriteProcessMemory(hProcess, foundAddr, &buffer[offset], pat.size(), nullptr);
                            startIt = it + pat.size();
                        }
                    }
                }
                DWORD temp = 0;
                VirtualProtectEx(hProcess, mbi.BaseAddress, mbi.RegionSize, oldProtect, &temp);
            }
        }

        address += mbi.RegionSize;
    }
    CloseHandle(hProcess);
}

void searchindexer()
{
    {
        HANDLE hToken = nullptr;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        {
            LUID luid;
            if (LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &luid))
            {
                TOKEN_PRIVILEGES tp;
                tp.PrivilegeCount = 1;
                tp.Privileges[0].Luid = luid;
                tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
                AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
            }
            CloseHandle(hToken);
        }
    }

    auto findProcessIdByName = [&](const std::wstring& processName) -> DWORD
        {
            DWORD pid = 0;
            HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (hSnap == INVALID_HANDLE_VALUE)
                return 0;

            PROCESSENTRY32W pe32{};
            pe32.dwSize = sizeof(pe32);

            if (Process32FirstW(hSnap, &pe32))
            {
                do
                {
                    if (!_wcsicmp(pe32.szExeFile, processName.c_str()))
                    {
                        pid = pe32.th32ProcessID;
                        break;
                    }
                } while (Process32NextW(hSnap, &pe32));
            }
            CloseHandle(hSnap);
            return pid;
        };

    auto patchMemory = [&](HANDLE hProcess, LPBYTE baseAddress, SIZE_T regionSize,
        const std::vector<BYTE>& fromBytes,
        const std::vector<BYTE>& toBytes) -> bool
        {
            if (fromBytes.size() != toBytes.size())
                return false;  // Uzunluklar e�le�meli

            std::vector<BYTE> buffer(regionSize);
            SIZE_T bytesRead = 0;
            if (!ReadProcessMemory(hProcess, baseAddress, buffer.data(), regionSize, &bytesRead))
                return false;

            bool foundAndPatched = false;
            for (size_t i = 0; i + fromBytes.size() <= bytesRead; i++)
            {
                if (memcmp(&buffer[i], fromBytes.data(), fromBytes.size()) == 0)
                {
                    // Bulundu, patch at
                    SIZE_T bytesWritten = 0;
                    if (WriteProcessMemory(hProcess, baseAddress + i, toBytes.data(), toBytes.size(), &bytesWritten))
                    {
                        foundAndPatched = true;
                    }
                }
            }

            return foundAndPatched;
        };

    struct PatternData
    {
        std::vector<BYTE> from;
        std::vector<BYTE> to;
        std::string name;
    };

    std::vector<PatternData> patterns =
    {
        {
            {0x63, 0x6D, 0x64, 0x2E, 0x65, 0x78, 0x65},
            {0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20},
            "cmd.exe"
        },
        {
            {0x70, 0x6F, 0x77, 0x65, 0x72, 0x73, 0x68, 0x65, 0x6C, 0x6C, 0x2E, 0x65, 0x78, 0x65},
            {0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20},
            "powershell.exe"
        },
        {
            {0x43, 0x3A, 0x5C, 0x50, 0x72, 0x6F, 0x67, 0x72, 0x61, 0x6D, 0x20, 0x46, 0x69, 0x6C, 0x65, 0x73, 0x5C, 0x50, 0x72, 0x6F, 0x74, 0x6F, 0x6E, 0x5C, 0x56, 0x50, 0x4E, 0x5C, 0x50, 0x72, 0x6F, 0x74, 0x6F, 0x6E, 0x56, 0x50, 0x4E, 0x2E, 0x4C, 0x61, 0x75, 0x6E, 0x63, 0x68, 0x65, 0x72, 0x2E, 0x65, 0x78, 0x65},
            {0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20},
            "C:\Program Files\Proton\VPN\PlanetVPN.exe"
        },
        {
            {0x73, 0x63, 0x76, 0x68, 0x6F, 0x73, 0x74},
            {0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20},
            "scvhost"
        },
        {
            {0x73, 0x63, 0x76, 0x68, 0x6F, 0x73, 0x74, 0x2E, 0x65, 0x78, 0x65},
            {0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20},
            "scvhost.exe"
        },
        {
            {0x57, 0x69, 0x6E, 0x52, 0x41, 0x52, 0x2E, 0x65, 0x78, 0x65},
            {0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20},
            "WinRAR.exe"
        },
        {
            {0x77, 0x69, 0x6E, 0x72, 0x61, 0x72, 0x2E, 0x65, 0x78, 0x65},
            {0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20},
            "winrar.exe"
        },
        {
            {0x73, 0x63, 0x76, 0x63, 0x68, 0x6F, 0x73, 0x74},
            {0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20},
            "scvchost"
        }
    };

    DWORD pid = findProcessIdByName(L"searchindexer.exe");
    if (pid == 0)
    {
        return;
    }

    HANDLE hProcess = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
        FALSE,
        pid
    );
    if (!hProcess)
    {
        return;
    }

    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    LPBYTE startAddress = (LPBYTE)sysInfo.lpMinimumApplicationAddress;
    LPBYTE endAddress = (LPBYTE)sysInfo.lpMaximumApplicationAddress;

    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T totalPatches = 0;

    for (LPBYTE current = startAddress; current < endAddress; )
    {
        if (!VirtualQueryEx(hProcess, current, &mbi, sizeof(mbi)))
            break;

        if (mbi.State == MEM_COMMIT &&
            !(mbi.Protect & PAGE_NOACCESS) &&
            !(mbi.Protect & PAGE_GUARD))
        {
            LPBYTE regionBase = (LPBYTE)mbi.BaseAddress;
            SIZE_T regionSize = mbi.RegionSize;

            for (auto& pat : patterns)
            {
                if (patchMemory(hProcess, regionBase, regionSize, pat.from, pat.to))
                {
                    totalPatches++;
                }
            }
        }

        current += mbi.RegionSize;
    }

    CloseHandle(hProcess);
}



struct LogEntry {
    DWORD EventID;
    std::wstring Message;
};