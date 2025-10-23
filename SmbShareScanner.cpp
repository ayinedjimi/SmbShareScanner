/*
Tool: SmbShareScanner
File: SmbShareScanner.cpp
Author: Ayi NEDJIMI Consultants
URL: https://www.ayinedjimi-consultants.fr
Version: 1.0
Description:
  Découvre et énumère les partages SMB sur le réseau local, analyse les permissions
  et signale les partages accessibles en écriture ou mal configurés.
Prerequisites:
  - Windows 10 / Windows Server 2016+ (x64)
  - Visual Studio Developer Command Prompt (x64)
  - Droits réseau pour énumération NetBIOS
Notes:
  - Outil en mode audit par défaut. Voir section LAB-CONTROLLED dans README pour démonstration en VM isolée.

WinToolsSuite – Security Tools for Network & Pentest
Developed by Ayi NEDJIMI Consultants
https://www.ayinedjimi-consultants.fr
© 2025 – Cybersecurity Research & Training
*/

#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <lm.h>
#include <commctrl.h>
#include <string>
#include <vector>
#include <sstream>
#include <fstream>
#include <thread>
#include <mutex>

#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "comctl32.lib")

#define WM_TOOL_RESULT   (WM_APP + 200)
#define WM_TOOL_ERROR    (WM_APP + 201)

#define IDC_LISTVIEW     1001
#define IDC_EDIT_SERVER  1002
#define IDC_BTN_SCAN     1003
#define IDC_BTN_EXPORT   1004
#define IDC_BTN_CLEAR    1005
#define ID_FILE_EXPORT   2001
#define ID_FILE_EXIT     2002
#define ID_HELP_ABOUT    2003

struct ShareInfo {
    std::wstring server;
    std::wstring shareName;
    std::wstring type;
    std::wstring comment;
    std::wstring permissions;
    std::wstring notes;
};

HWND g_hwnd = NULL;
HWND g_hwndList = NULL;
HWND g_hwndEdit = NULL;
std::vector<ShareInfo> g_shares;
std::mutex g_mutex;
std::wofstream g_logFile;
bool g_scanning = false;
std::thread g_scanThread;

void LogMessage(const std::wstring& msg) {
    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t timeBuf[100];
    swprintf_s(timeBuf, L"[%04d-%02d-%02d %02d:%02d:%02d] ",
               st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    if (g_logFile.is_open()) {
        g_logFile << timeBuf << msg << std::endl;
        g_logFile.flush();
    }
}

void InitLog() {
    wchar_t tempPath[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);
    std::wstring logPath = std::wstring(tempPath) + L"WinTools_SmbShareScanner_log.txt";
    g_logFile.open(logPath, std::ios::app);
    LogMessage(L"=== SmbShareScanner démarré ===");
}

std::wstring ShareTypeToString(DWORD type) {
    switch (type & ~STYPE_SPECIAL) {
        case STYPE_DISKTREE: return L"Disque";
        case STYPE_PRINTQ: return L"Imprimante";
        case STYPE_DEVICE: return L"Périphérique";
        case STYPE_IPC: return L"IPC";
        default: return L"Autre";
    }
}

void ScanServer(const std::wstring& serverName) {
    LogMessage(L"Scan serveur: " + serverName);

    PSHARE_INFO_1 pBuf = NULL;
    DWORD entriesRead = 0;
    DWORD totalEntries = 0;
    DWORD resumeHandle = 0;

    NET_API_STATUS status = NetShareEnum(
        serverName.c_str(),
        1,
        (LPBYTE*)&pBuf,
        MAX_PREFERRED_LENGTH,
        &entriesRead,
        &totalEntries,
        &resumeHandle
    );

    if (status != NERR_Success) {
        LogMessage(L"Échec NetShareEnum: " + serverName);
        PostMessageW(g_hwnd, WM_TOOL_ERROR, 0, 0);
        return;
    }

    for (DWORD i = 0; i < entriesRead; i++) {
        ShareInfo info = {};
        info.server = serverName;
        info.shareName = pBuf[i].shi1_netname;
        info.type = ShareTypeToString(pBuf[i].shi1_type);
        info.comment = pBuf[i].shi1_remark ? pBuf[i].shi1_remark : L"";

        // Essayer de récupérer permissions (niveau 502)
        PSHARE_INFO_502 pInfo502 = NULL;
        if (NetShareGetInfo(serverName.c_str(), pBuf[i].shi1_netname, 502, (LPBYTE*)&pInfo502) == NERR_Success) {
            if (pInfo502->shi502_permissions & ACCESS_ALL) {
                info.permissions = L"Tous";
                info.notes = L"⚠ Partage accessible à tous";
            } else if (pInfo502->shi502_permissions & ACCESS_WRITE) {
                info.permissions = L"Écriture";
                info.notes = L"⚠ Écriture autorisée";
            } else {
                info.permissions = L"Lecture";
                info.notes = L"OK";
            }
            NetApiBufferFree(pInfo502);
        } else {
            info.permissions = L"Inconnu";
            info.notes = L"Impossible de récupérer permissions";
        }

        // Ignorer partages administratifs cachés par défaut
        if (info.shareName.back() == L'$') {
            info.notes = L"Partage administratif";
        }

        {
            std::lock_guard<std::mutex> lock(g_mutex);
            g_shares.push_back(info);
        }
    }

    if (pBuf) NetApiBufferFree(pBuf);

    PostMessageW(g_hwnd, WM_TOOL_RESULT, 0, 0);
    LogMessage(L"Scan terminé: " + serverName);
}

void ScanThread(std::wstring server) {
    ScanServer(server);
    g_scanning = false;
}

void UpdateListView() {
    ListView_DeleteAllItems(g_hwndList);

    std::lock_guard<std::mutex> lock(g_mutex);

    int index = 0;
    for (const auto& share : g_shares) {
        LVITEMW lvi = {};
        lvi.mask = LVIF_TEXT;
        lvi.iItem = index;
        lvi.iSubItem = 0;
        lvi.pszText = const_cast<LPWSTR>(share.server.c_str());
        ListView_InsertItem(g_hwndList, &lvi);

        ListView_SetItemText(g_hwndList, index, 1, const_cast<LPWSTR>(share.shareName.c_str()));
        ListView_SetItemText(g_hwndList, index, 2, const_cast<LPWSTR>(share.type.c_str()));
        ListView_SetItemText(g_hwndList, index, 3, const_cast<LPWSTR>(share.comment.c_str()));
        ListView_SetItemText(g_hwndList, index, 4, const_cast<LPWSTR>(share.permissions.c_str()));
        ListView_SetItemText(g_hwndList, index, 5, const_cast<LPWSTR>(share.notes.c_str()));

        index++;
    }
}

void ExportToCsv(const std::wstring& filename) {
    std::wofstream file(filename);
    if (!file.is_open()) {
        MessageBoxW(g_hwnd, L"Impossible de créer le fichier CSV", L"Erreur", MB_OK | MB_ICONERROR);
        return;
    }

    file.put(0xFEFF);
    file << L"Serveur,Partage,Type,Commentaire,Permissions,Notes\n";

    std::lock_guard<std::mutex> lock(g_mutex);
    for (const auto& share : g_shares) {
        file << L"\"" << share.server << L"\",";
        file << L"\"" << share.shareName << L"\",";
        file << L"\"" << share.type << L"\",";
        file << L"\"" << share.comment << L"\",";
        file << L"\"" << share.permissions << L"\",";
        file << L"\"" << share.notes << L"\"\n";
    }

    file.close();
    MessageBoxW(g_hwnd, L"Export CSV réussi", L"Information", MB_OK | MB_ICONINFORMATION);
    LogMessage(L"Export CSV: " + filename);
}

void ShowAboutDialog() {
    MessageBoxW(g_hwnd,
        L"SmbShareScanner v1.0\n\n"
        L"Découvre et analyse les partages SMB réseau\n\n"
        L"WinToolsSuite – Security Tools for Network & Pentest\n"
        L"Developed by Ayi NEDJIMI Consultants\n"
        L"https://www.ayinedjimi-consultants.fr\n"
        L"© 2025 – Cybersecurity Research & Training",
        L"À propos",
        MB_OK | MB_ICONINFORMATION);
}

void InitListView(HWND hwndList) {
    LVCOLUMNW lvc = {};
    lvc.mask = LVCF_TEXT | LVCF_WIDTH;

    lvc.cx = 150;
    lvc.pszText = const_cast<LPWSTR>(L"Serveur");
    ListView_InsertColumn(hwndList, 0, &lvc);

    lvc.cx = 150;
    lvc.pszText = const_cast<LPWSTR>(L"Partage");
    ListView_InsertColumn(hwndList, 1, &lvc);

    lvc.cx = 100;
    lvc.pszText = const_cast<LPWSTR>(L"Type");
    ListView_InsertColumn(hwndList, 2, &lvc);

    lvc.cx = 200;
    lvc.pszText = const_cast<LPWSTR>(L"Commentaire");
    ListView_InsertColumn(hwndList, 3, &lvc);

    lvc.cx = 120;
    lvc.pszText = const_cast<LPWSTR>(L"Permissions");
    ListView_InsertColumn(hwndList, 4, &lvc);

    lvc.cx = 220;
    lvc.pszText = const_cast<LPWSTR>(L"Notes");
    ListView_InsertColumn(hwndList, 5, &lvc);

    ListView_SetExtendedListViewStyle(hwndList, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE: {
            HMENU hMenu = CreateMenu();
            HMENU hFileMenu = CreateMenu();
            AppendMenuW(hFileMenu, MF_STRING, ID_FILE_EXPORT, L"&Exporter CSV...");
            AppendMenuW(hFileMenu, MF_SEPARATOR, 0, NULL);
            AppendMenuW(hFileMenu, MF_STRING, ID_FILE_EXIT, L"&Quitter");
            AppendMenuW(hMenu, MF_POPUP, (UINT_PTR)hFileMenu, L"&Fichier");

            HMENU hHelpMenu = CreateMenu();
            AppendMenuW(hHelpMenu, MF_STRING, ID_HELP_ABOUT, L"&À propos...");
            AppendMenuW(hMenu, MF_POPUP, (UINT_PTR)hHelpMenu, L"&Aide");
            SetMenu(hwnd, hMenu);

            CreateWindowExW(0, L"STATIC", L"Serveur:",
                WS_CHILD | WS_VISIBLE,
                10, 15, 80, 20,
                hwnd, NULL, GetModuleHandle(NULL), NULL);

            g_hwndEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"\\\\localhost",
                WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
                90, 12, 400, 24,
                hwnd, (HMENU)IDC_EDIT_SERVER, GetModuleHandle(NULL), NULL);

            CreateWindowExW(0, L"BUTTON", L"Scanner",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                500, 12, 100, 24,
                hwnd, (HMENU)IDC_BTN_SCAN, GetModuleHandle(NULL), NULL);

            g_hwndList = CreateWindowExW(0, WC_LISTVIEWW, L"",
                WS_CHILD | WS_VISIBLE | WS_BORDER | LVS_REPORT,
                10, 50, 980, 380,
                hwnd, (HMENU)IDC_LISTVIEW, GetModuleHandle(NULL), NULL);
            InitListView(g_hwndList);

            CreateWindowExW(0, L"BUTTON", L"Exporter CSV",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                10, 440, 150, 30,
                hwnd, (HMENU)IDC_BTN_EXPORT, GetModuleHandle(NULL), NULL);

            CreateWindowExW(0, L"BUTTON", L"Effacer",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                170, 440, 150, 30,
                hwnd, (HMENU)IDC_BTN_CLEAR, GetModuleHandle(NULL), NULL);

            break;
        }

        case WM_COMMAND: {
            int wmId = LOWORD(wParam);
            switch (wmId) {
                case IDC_BTN_SCAN: {
                    if (g_scanning) {
                        MessageBoxW(hwnd, L"Un scan est déjà en cours", L"Information", MB_OK);
                        break;
                    }

                    wchar_t server[512] = {};
                    GetWindowTextW(g_hwndEdit, server, 512);
                    if (wcslen(server) == 0) {
                        MessageBoxW(hwnd, L"Veuillez entrer un serveur", L"Erreur", MB_OK | MB_ICONERROR);
                        break;
                    }

                    g_scanning = true;
                    if (g_scanThread.joinable()) g_scanThread.join();
                    g_scanThread = std::thread(ScanThread, std::wstring(server));
                    break;
                }

                case IDC_BTN_EXPORT:
                case ID_FILE_EXPORT: {
                    wchar_t filename[MAX_PATH] = L"shares.csv";
                    OPENFILENAMEW ofn = {};
                    ofn.lStructSize = sizeof(ofn);
                    ofn.hwndOwner = hwnd;
                    ofn.lpstrFile = filename;
                    ofn.nMaxFile = MAX_PATH;
                    ofn.lpstrFilter = L"CSV Files\0*.csv\0All Files\0*.*\0";
                    ofn.Flags = OFN_OVERWRITEPROMPT;
                    if (GetSaveFileNameW(&ofn)) {
                        ExportToCsv(filename);
                    }
                    break;
                }

                case IDC_BTN_CLEAR:
                    {
                        std::lock_guard<std::mutex> lock(g_mutex);
                        g_shares.clear();
                    }
                    UpdateListView();
                    LogMessage(L"Résultats effacés");
                    break;

                case ID_FILE_EXIT:
                    PostMessageW(hwnd, WM_CLOSE, 0, 0);
                    break;

                case ID_HELP_ABOUT:
                    ShowAboutDialog();
                    break;
            }
            break;
        }

        case WM_TOOL_RESULT:
            UpdateListView();
            break;

        case WM_TOOL_ERROR:
            MessageBoxW(hwnd, L"Impossible d'énumérer les partages.\nVérifiez le nom du serveur et l'accès réseau.",
                       L"Erreur", MB_OK | MB_ICONERROR);
            g_scanning = false;
            break;

        case WM_DESTROY:
            g_scanning = false;
            if (g_scanThread.joinable()) g_scanThread.join();
            if (g_logFile.is_open()) {
                LogMessage(L"=== SmbShareScanner arrêté ===");
                g_logFile.close();
            }
            PostQuitMessage(0);
            break;

        default:
            return DefWindowProcW(hwnd, msg, wParam, lParam);
    }
    return 0;
}

int APIENTRY wWinMain(HINSTANCE hInstance, HINSTANCE, LPWSTR, int nCmdShow) {
    InitLog();

    INITCOMMONCONTROLSEX icex = {};
    icex.dwSize = sizeof(icex);
    icex.dwICC = ICC_LISTVIEW_CLASSES;
    InitCommonControlsEx(&icex);

    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"SmbShareScanner";

    RegisterClassExW(&wc);

    g_hwnd = CreateWindowExW(0, L"SmbShareScanner",
        L"SmbShareScanner - Énumération Partages SMB",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 1020, 540,
        NULL, NULL, hInstance, NULL);

    if (!g_hwnd) return 1;

    ShowWindow(g_hwnd, nCmdShow);
    UpdateWindow(g_hwnd);

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    return (int)msg.wParam;
}
