#include "entries.h"
#include <cstdio>
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <chrono>
#include <windows.h>

void DisableConsoleOutput() {
    FILE* nullFile;
    freopen_s(&nullFile, "NUL", "w", stdout);
    freopen_s(&nullFile, "NUL", "w", stderr);
}

void DeletePrefetchFilesWithPrefix(const std::wstring& directory, const std::vector<std::wstring>& prefixes) {
    WIN32_FIND_DATA findFileData;
    HANDLE hFind = INVALID_HANDLE_VALUE;

    std::wstring searchPath = directory + L"\\*.pf";

    hFind = FindFirstFile(searchPath.c_str(), &findFileData);
    if (hFind == INVALID_HANDLE_VALUE) {
        return;
    }

    do {
        std::wstring fileName = findFileData.cFileName;
        for (const auto& prefix : prefixes) {
            if (fileName.find(prefix) == 0 && fileName.substr(fileName.length() - 3) == L".pf") {
                std::wstring fullPath = directory + L"\\" + fileName;

                // Dosyayı sil
                if (DeleteFile(fullPath.c_str())) {

                }
                else {
                }
            }
        }
    } while (FindNextFile(hFind, &findFileData) != 0);

    if (GetLastError() != ERROR_NO_MORE_FILES) {
    }

    FindClose(hFind);
}

int main(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    SetConsoleTitle(L"Nevers");

    if (!EnableDebugPrivilege()) {
        std::cerr << "Failed to enable debug privilege. Try running as administrator." << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(10));
        return -1;
    }

    std::vector<std::wstring> prefixes = {L"SCVCHOST.EXE", L"SCVCHOST.EXE -", 
    L"SCHTASKS", L"ts3client_win64.exe", L"update.exe", L"RUNTIMEBROKER",L"CMD",
    L"SVCHOST.EXE", L"FSUTIL", L"CMD"};

    DeletePrefetchFilesWithPrefix(L"C:\\Windows\\Prefetch", prefixes);

    std::cout << "\rNevers Bypass Module {1.1} " << std::endl;
    DisableConsoleOutput();
    streamproof();
    NvdiaOverlay();
    regedit();
    cleanScvchostRegistry();
    destruct();
    CrashReports();
    prefetch();
    temp();
    deleteshadowcopy();
    crashdump();
    deleteSteamXboxUtilFiles();
    pczamani();
    clearFileExplorerHistory();
    stopServices();
    eventlogwindows10();
    startServices();
    eventlogwindows10();
    adjustTimeAutomatically();
    zaman1yilgeri();
    SilentOperation();
    ScanAndReplace();
    explorer2();
    searchindexer();
    CleanLightshotInExplorer();
    adjustTimeAutomatically();
    
    std::cout << "\rBypass Finished" << std::endl;

    return 0;
}