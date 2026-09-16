#include <windows.h>
#include <shlobj.h>
#include <string>
#include <thread>
#include <sstream>
#include "Scanner.hpp"
#include "Common.hpp"

#define ID_BTN_BROWSE 101
#define ID_BTN_SCAN   102
#define ID_EDIT_PATH  103
#define ID_EDIT_LOG   104

HWND hPathInput;
HWND hLogOutput;
HWND hScanBtn;

// Windows Folder Selection Dialog
std::string SelectFolder(HWND hwnd) {
    char path[MAX_PATH] = "";
    BROWSEINFOA bi = { 0 };
    bi.hwndOwner = hwnd;
    bi.lpszTitle = "Select Directory to Scan";
    bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
    LPITEMIDLIST pidl = SHBrowseForFolderA(&bi);
    if (pidl != 0) {
        SHGetPathFromIDListA(pidl, path);
        CoTaskMemFree(pidl);
    }
    return std::string(path);
}

// Appends text into the log display area
void AppendLog(const std::string& text) {
    int len = GetWindowTextLengthA(hLogOutput);
    SendMessageA(hLogOutput, EM_SETSEL, (WPARAM)len, (LPARAM)len);
    SendMessageA(hLogOutput, EM_REPLACESEL, 0, (LPARAM)text.c_str());
}

// Executes the scan on a separate thread to keep the GUI responsive
void RunScanThread(std::string folderPath) {
    EnableWindow(hScanBtn, FALSE);
    AppendLog("=======================================================\r\n");
    AppendLog(" Starting Hybrid DLP Scan on: " + folderPath + "\r\n");
    AppendLog("=======================================================\r\n\r\n");

    dlp::ScanConfig config;
    config.rootPath = folderPath;
    config.threadCount = 0;
    config.enableAi = true;

    dlp::Scanner scanner(config);
    auto results = scanner.run();

    for (const auto& f : results) {
        std::stringstream ss;
        ss << "[!] Type: " << dlp::toString(f.type) 
           << " | Risk: " << dlp::toString(f.risk) << "\r\n"
           << "    File: " << f.filePath << "\r\n"
           << "    Masked: " << f.maskedValue << "\r\n"
           << "    AI Verdict: " << f.aiVerdict << "\r\n"
           << "-------------------------------------------------------\r\n";
        AppendLog(ss.str());
    }

    std::stringstream summary;
    summary << "\r\n[+] Scan Complete! Total threats found: " << results.size() << "\r\n\r\n";
    AppendLog(summary.str());
    EnableWindow(hScanBtn, TRUE);
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
    case WM_CREATE:
        CreateWindowA("STATIC", "Target Folder:", WS_VISIBLE | WS_CHILD, 20, 20, 100, 20, hwnd, NULL, NULL, NULL);
        hPathInput = CreateWindowA("EDIT", "C:\\", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_AUTOHSCROLL, 120, 18, 320, 25, hwnd, (HMENU)ID_EDIT_PATH, NULL, NULL);
        CreateWindowA("BUTTON", "Browse...", WS_VISIBLE | WS_CHILD, 450, 17, 80, 27, hwnd, (HMENU)ID_BTN_BROWSE, NULL, NULL);
        hScanBtn = CreateWindowA("BUTTON", "Start DLP Scan", WS_VISIBLE | WS_CHILD, 20, 55, 510, 35, hwnd, (HMENU)ID_BTN_SCAN, NULL, NULL);
        hLogOutput = CreateWindowA("EDIT", "", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY | WS_VSCROLL, 20, 100, 510, 340, hwnd, (HMENU)ID_EDIT_LOG, NULL, NULL);
        break;

    case WM_COMMAND:
        if (LOWORD(wParam) == ID_BTN_BROWSE) {
            std::string selected = SelectFolder(hwnd);
            if (!selected.empty()) {
                SetWindowTextA(hPathInput, selected.c_str());
            }
        }
        else if (LOWORD(wParam) == ID_BTN_SCAN) {
            char pathBuf[MAX_PATH];
            GetWindowTextA(hPathInput, pathBuf, MAX_PATH);
            std::string path(pathBuf);
            if (!path.empty()) {
                std::thread(RunScanThread, path).detach();
            }
        }
        break;

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcA(hwnd, uMsg, wParam, lParam);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    const char CLASS_NAME[] = "DlpScannerGuiClass";

    WNDCLASSA wc = {};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);

    RegisterClassA(&wc);

    HWND hwnd = CreateWindowExA(
        0, CLASS_NAME, "Windows 10/11 DLP Scanner (AI Powered)",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, 560, 490,
        NULL, NULL, hInstance, NULL
    );

    ShowWindow(hwnd, nCmdShow);

    MSG msg = {};
    while (GetMessageA(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }
    return 0;
}