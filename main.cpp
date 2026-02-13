// FileSyncer/main.cpp
// Win32 GUI app that watches process start/stop via WMI and performs per-app sync rules:
//
// Rule = { AppExePath, LocalPath, ServerPath }
//
// Behavior:
// - When a process STARTS and its ExecutablePath matches a rule's AppExePath:
//     Copy ServerPath -> LocalPath
// - When the process STOPS (close/exit) and it matched a rule:
//     Copy LocalPath -> ServerPath
//
// GUI:
// - Add/Remove/Clear/Load/Save rules
// - On-screen log view with Copy/Clear
// - System tray behavior: closing the window minimizes to tray; restore/exit from tray menu
//
// Notes:
// - Paths are matched case-insensitively using normalized full paths.
// - Copy behavior:
//   - Directories: mirrored using robocopy (/MIR)
//   - Files: copied using SHFileOperationW
// Command:
// cl /EHsc /std:c++17 /O2 /DUNICODE /D_UNICODE /FeFileSyncer.exe main.cpp ole32.lib oleaut32.lib wbemuuid.lib comctl32.lib shlwapi.lib shell32.lib gdi32.lib /link /SUBSYSTEM:WINDOWS

#include <windows.h>
#include <commctrl.h>
#include <shlwapi.h>
#include <shellapi.h>
#include <wbemidl.h>
#include <comdef.h>

#include <atomic>
#include <mutex>
#include <string>
#include <vector>
#include <unordered_map>
#include <algorithm>
#include <fstream>
#include <sstream>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "shell32.lib")

// --------------------------- Utilities ---------------------------

static std::wstring Trim(const std::wstring& s) {
    size_t b = 0;
    while (b < s.size() && iswspace(s[b])) b++;
    size_t e = s.size();
    while (e > b && iswspace(s[e - 1])) e--;
    return s.substr(b, e - b);
}

static std::wstring StripWrappingQuotes(const std::wstring& s) {
    if (s.size() >= 2 && ((s.front() == L'"' && s.back() == L'"') || (s.front() == L'\'' && s.back() == L'\''))) {
        return s.substr(1, s.size() - 2);
    }
    return s;
}

static std::wstring ToLower(const std::wstring& s) {
    std::wstring out = s;
    std::transform(out.begin(), out.end(), out.begin(), [](wchar_t c) { return (wchar_t)towlower(c); });
    return out;
}

static std::wstring ExpandEnvVars(const std::wstring& in) {
    if (in.empty()) return in;
    DWORD needed = ExpandEnvironmentStringsW(in.c_str(), nullptr, 0);
    if (needed == 0) return in;
    std::wstring out;
    out.resize(needed);
    DWORD written = ExpandEnvironmentStringsW(in.c_str(), out.data(), needed);
    if (written == 0) return in;
    // ExpandEnvironmentStrings includes null terminator in written count
    if (!out.empty() && out.back() == L'\0') out.pop_back();
    return out;
}

static std::wstring NormalizePath(const std::wstring& raw) {
    std::wstring s = Trim(raw);
    s = StripWrappingQuotes(s);
    s = Trim(s);
    s = ExpandEnvVars(s);

    // If it's still empty, return empty.
    if (s.empty()) return s;

    // Get full path (handles relative paths).
    wchar_t buf[MAX_PATH * 8] = {0};
    DWORD len = GetFullPathNameW(s.c_str(), (DWORD)_countof(buf), buf, nullptr);
    std::wstring full = (len > 0 && len < _countof(buf)) ? std::wstring(buf, len) : s;

    // Normalize slashes to backslashes
    for (auto& ch : full) {
        if (ch == L'/') ch = L'\\';
    }

    // Remove trailing backslash for non-root paths
    if (full.size() > 3 && !full.empty() && (full.back() == L'\\')) {
        full.pop_back();
    }

    return ToLower(full);
}

static SYSTEMTIME NowLocalTime() {
    SYSTEMTIME st;
    GetLocalTime(&st);
    return st;
}

static std::wstring FormatTimestamp(const SYSTEMTIME& st) {
    wchar_t buf[64];
    swprintf_s(buf, L"%04u-%02u-%02u %02u:%02u:%02u.%03u",
               st.wYear, st.wMonth, st.wDay,
               st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    return buf;
}

static std::wstring JoinLines(const std::vector<std::wstring>& lines) {
    std::wstring out;
    for (size_t i = 0; i < lines.size(); ++i) {
        out += lines[i];
        if (i + 1 < lines.size()) out += L"\r\n";
    }
    return out;
}

static void SetClipboardText(HWND hwndOwner, const std::wstring& text) {
    if (!OpenClipboard(hwndOwner)) return;
    EmptyClipboard();
    size_t bytes = (text.size() + 1) * sizeof(wchar_t);
    HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, bytes);
    if (hMem) {
        void* p = GlobalLock(hMem);
        if (p) {
            memcpy(p, text.c_str(), bytes);
            GlobalUnlock(hMem);
            SetClipboardData(CF_UNICODETEXT, hMem);
            // system owns memory after SetClipboardData
        } else {
            GlobalFree(hMem);
        }
    }
    CloseClipboard();
}

static std::wstring GetExeDir() {
    wchar_t path[MAX_PATH] = {0};
    DWORD n = GetModuleFileNameW(nullptr, path, _countof(path));
    if (n == 0 || n >= _countof(path)) return L".";
    PathRemoveFileSpecW(path);
    return path;
}

static std::wstring DefaultRulesFilePath() {
    std::wstring dir = GetExeDir();
    return dir + L"\\rules.txt";
}



// SHFileOperation needs double-NUL terminated strings.
static std::wstring MakeDoubleNullPath(const std::wstring& p) {
    std::wstring s = p;
    s.push_back(L'\0');
    s.push_back(L'\0');
    return s;
}

static bool PathExistsAny(const std::wstring& path) {
    DWORD attr = GetFileAttributesW(path.c_str());
    return (attr != INVALID_FILE_ATTRIBUTES);
}

static bool IsDirectoryPath(const std::wstring& path) {
    DWORD attr = GetFileAttributesW(path.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES) return false;
    return (attr & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

// Best-effort create directory tree for a directory path.
static bool EnsureDirectoryExists(const std::wstring& dirPath) {
    if (dirPath.empty()) return false;
    if (PathIsRootW(dirPath.c_str())) return true;
    if (CreateDirectoryW(dirPath.c_str(), nullptr)) return true;
    DWORD err = GetLastError();
    if (err == ERROR_ALREADY_EXISTS) return true;

    // Recurse on parent
    wchar_t buf[MAX_PATH * 8] = {0};
    wcsncpy_s(buf, dirPath.c_str(), _TRUNCATE);
    PathRemoveFileSpecW(buf);
    std::wstring parent = buf;
    if (!parent.empty() && parent != dirPath) {
        if (!EnsureDirectoryExists(parent)) return false;
        if (CreateDirectoryW(dirPath.c_str(), nullptr)) return true;
        err = GetLastError();
        return err == ERROR_ALREADY_EXISTS;
    }
    return false;
}

// Forward declaration: sync helpers log failures.
static void AppendLogLine(const std::wstring& line);

#pragma comment(lib, "mpr.lib")
#include <winnetwk.h>

static void RefreshNetworkShareConnection(const std::wstring& path) {
    // Only interested in UNC paths: \\server\share...
    if (path.size() < 3 || path[0] != L'\\' || path[1] != L'\\') return;

    // Find the server/share part. 
    // Format: \\server\share\remainder
    size_t serverEnd = path.find(L'\\', 2);
    if (serverEnd == std::wstring::npos) return; // Just \\server ?

    size_t shareEnd = path.find(L'\\', serverEnd + 1);
    std::wstring sharePath;
    if (shareEnd == std::wstring::npos) {
        sharePath = path;
    } else {
        sharePath = path.substr(0, shareEnd);
    }

    // Drop any existing connection to force a refresh
    WNetCancelConnection2W(sharePath.c_str(), 0, FALSE);

    // Re-establish using current user context
    NETRESOURCEW nr{};
    nr.dwType = RESOURCETYPE_DISK;
    nr.lpRemoteName = const_cast<wchar_t*>(sharePath.c_str());
    nr.lpLocalName = nullptr;
    nr.lpProvider = nullptr;

    WNetAddConnection2W(&nr, nullptr, nullptr, 0);
}

// Copy a single file using SHFileOperationW.
static bool CopyFileShFileOp(const std::wstring& src, const std::wstring& dst) {
    if (src.empty() || dst.empty()) return false;

    // Ensure destination parent exists
    wchar_t buf[MAX_PATH * 8] = {0};
    wcsncpy_s(buf, dst.c_str(), _TRUNCATE);
    PathRemoveFileSpecW(buf);
    EnsureDirectoryExists(buf);

    SHFILEOPSTRUCTW op{};
    op.wFunc = FO_COPY;
    std::wstring from = MakeDoubleNullPath(src);
    std::wstring to = MakeDoubleNullPath(dst);
    op.pFrom = from.c_str();
    op.pTo = to.c_str();
    op.fFlags = FOF_NOCONFIRMMKDIR | FOF_NOCONFIRMATION | FOF_SILENT | FOF_NOERRORUI;
    int res = SHFileOperationW(&op);

    return (res == 0) && !op.fAnyOperationsAborted;
}

// Mirror a directory using robocopy (/MIR). Returns true if robocopy exit code indicates success.
// Robocopy exit codes: 0-7 typical success/warnings; >=8 indicates failure.
static bool MirrorDirectoryRobocopy(const std::wstring& srcDir, const std::wstring& dstDir) {
    if (srcDir.empty() || dstDir.empty()) return false;

    // Ensure destination exists (robocopy will also create, but this avoids odd edge cases)
    EnsureDirectoryExists(dstDir);

    // Robocopy expects the source directory (not "source\\*").
    // `robocopy SRC DST /MIR` mirrors SRC's contents onto DST.
    std::wstring cmd = L"robocopy \"" + srcDir + L"\" \"" + dstDir +
                       L"\" /MIR /R:1 /W:1 /NP /FFT";

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};

    // CreateProcess requires a mutable buffer
    std::vector<wchar_t> mutableCmd(cmd.begin(), cmd.end());
    mutableCmd.push_back(L'\0');

    BOOL ok = CreateProcessW(
        nullptr,
        mutableCmd.data(),
        nullptr,
        nullptr,
        FALSE,
        CREATE_NO_WINDOW,
        nullptr,
        nullptr,
        &si,
        &pi
    );

    if (!ok) return false;

    WaitForSingleObject(pi.hProcess, INFINITE);

    DWORD exitCode = 9999;
    GetExitCodeProcess(pi.hProcess, &exitCode);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    // Robocopy: 0-7 are success/warnings, >=8 indicates failure.
    return exitCode <= 7;
}

// Copy entry point used by sync:
// - If src is a directory: robocopy /MIR
// - If src is a file: SHFileOperationW copy
static bool SyncCopyPath(const std::wstring& src, const std::wstring& dst) {
    if (src.empty() || dst.empty()) return false;

    if (IsDirectoryPath(src)) {
        return MirrorDirectoryRobocopy(src, dst);
    }

    return CopyFileShFileOp(src, dst);
}

// --------------------------- GUI IDs ---------------------------

enum : int {
    IDC_APP_EDIT      = 1001,
    IDC_LOCAL_EDIT    = 1002,
    IDC_SERVER_EDIT   = 1003,

    IDC_ADD_BTN       = 1010,
    IDC_REMOVE_BTN    = 1011,
    IDC_CLEAR_BTN     = 1012,
    IDC_LOAD_BTN      = 1013,
    IDC_SAVE_BTN      = 1014,

    IDC_RULES_LIST    = 1020,

    IDC_LOG_EDIT      = 2001,
    IDC_LOG_CLEAR_BTN = 2002,
    IDC_LOG_COPY_BTN  = 2003,

    IDC_STATUS        = 3001,

    // System tray
    WM_APP_TRAY       = WM_APP + 10,
    ID_TRAY_RESTORE   = 4001,
    ID_TRAY_EXIT      = 4002,

    WM_APP_LOG        = WM_APP + 1,
    WM_APP_COUNTS     = WM_APP + 2,

    TIMER_HEARTBEAT   = 1
};

// --------------------------- App State ---------------------------

struct SyncRule {
    // Normalized for matching
    std::wstring appExeNorm;
    // Display/original values
    std::wstring appExe;
    std::wstring localPath;
    std::wstring serverPath;
};



struct AppState {
    HWND hwndMain = nullptr;

    HWND hAppEdit = nullptr;
    HWND hLocalEdit = nullptr;
    HWND hServerEdit = nullptr;

    HWND hAddBtn = nullptr;
    HWND hRemoveBtn = nullptr;
    HWND hClearBtn = nullptr;
    HWND hLoadBtn = nullptr;
    HWND hSaveBtn = nullptr;
    HWND hRulesList = nullptr;

    HWND hLogEdit = nullptr;
    HWND hLogClear = nullptr;
    HWND hLogCopy = nullptr;

    HWND hStatus = nullptr;

    // Tray state
    NOTIFYICONDATAW tray{};
    bool trayAdded = false;
    bool allowExit = false;

    std::mutex rulesMutex;
    std::vector<SyncRule> rules; // listbox index matches this vector index

    std::atomic<long> startCount{0};
    std::atomic<long> stopCount{0};

    // WMI objects
    IWbemLocator* pLoc = nullptr;
    IWbemServices* pSvc = nullptr;
    IUnknown* pSinkUnk = nullptr; // EventSink

    std::atomic<bool> wmiActive{false};
};

static AppState g_app;

// --------------------------- Filter Logic ---------------------------

static std::wstring RuleToDisplayLine(const SyncRule& r) {
    // Keep it human-readable in a single line.
    return r.appExe + L"   |   local: " + r.localPath + L"   |   server: " + r.serverPath;
}

// Forward declaration: used by AddRule (defined later).
static void ReloadRulesListUIFromState();

static void AddRule(const std::wstring& appExeRaw, const std::wstring& localRaw, const std::wstring& serverRaw) {
    SyncRule r;
    r.appExe = Trim(StripWrappingQuotes(appExeRaw));
    r.localPath = Trim(StripWrappingQuotes(localRaw));
    r.serverPath = Trim(StripWrappingQuotes(serverRaw));
    r.appExeNorm = NormalizePath(r.appExe);
    if (r.appExeNorm.empty() || r.localPath.empty() || r.serverPath.empty()) return;
    std::wstring lNorm = NormalizePath(r.localPath), sNorm = NormalizePath(r.serverPath);
    {
        std::lock_guard<std::mutex> lock(g_app.rulesMutex);
        for (const auto& ex : g_app.rules) {
            if (ex.appExeNorm == r.appExeNorm && NormalizePath(ex.localPath) == lNorm && NormalizePath(ex.serverPath) == sNorm) return;
        }
        g_app.rules.push_back(r);
    }
    SendMessageW(g_app.hRulesList, LB_ADDSTRING, 0, (LPARAM)RuleToDisplayLine(r).c_str());
}

static void RemoveSelectedRule() {
    int sel = (int)SendMessageW(g_app.hRulesList, LB_GETCURSEL, 0, 0);
    if (sel == LB_ERR) return;

    {
        std::lock_guard<std::mutex> lock(g_app.rulesMutex);
        if (sel >= 0 && (size_t)sel < g_app.rules.size()) {
            g_app.rules.erase(g_app.rules.begin() + sel);
        }
    }
    SendMessageW(g_app.hRulesList, LB_DELETESTRING, sel, 0);
}

static void ClearRules() {
    {
        std::lock_guard<std::mutex> lock(g_app.rulesMutex);
        g_app.rules.clear();
    }
    SendMessageW(g_app.hRulesList, LB_RESETCONTENT, 0, 0);
}

static void ReloadRulesListUIFromState() {
    SendMessageW(g_app.hRulesList, LB_RESETCONTENT, 0, 0);
    std::lock_guard<std::mutex> lock(g_app.rulesMutex);
    for (const auto& r : g_app.rules) {
        SendMessageW(g_app.hRulesList, LB_ADDSTRING, 0, (LPARAM)RuleToDisplayLine(r).c_str());
    }
}

static void TrayAddOrUpdate(HWND hwnd) {
    if (!hwnd) return;

    if (!g_app.trayAdded) {
        ZeroMemory(&g_app.tray, sizeof(g_app.tray));
        g_app.tray.cbSize = sizeof(g_app.tray);
        g_app.tray.hWnd = hwnd;
        g_app.tray.uID = 1;
        g_app.tray.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
        g_app.tray.uCallbackMessage = WM_APP_TRAY;
        g_app.tray.hIcon = (HICON)LoadIconW(nullptr, IDI_APPLICATION);
        lstrcpynW(g_app.tray.szTip, L"FileSyncer", _countof(g_app.tray.szTip));

        g_app.trayAdded = Shell_NotifyIconW(NIM_ADD, &g_app.tray) != FALSE;
    } else {
        Shell_NotifyIconW(NIM_MODIFY, &g_app.tray);
    }
}

static void TrayRemove() {
    if (g_app.trayAdded) {
        Shell_NotifyIconW(NIM_DELETE, &g_app.tray);
        g_app.trayAdded = false;
        ZeroMemory(&g_app.tray, sizeof(g_app.tray));
    }
}

static void HideToTray(HWND hwnd) {
    TrayAddOrUpdate(hwnd);
    // Hide the window (do NOT minimize after hiding; that can keep it in an odd invisible/minimized state).
    ShowWindow(hwnd, SW_HIDE);
}

static void RestoreFromTray(HWND hwnd) {
    // Show + restore and explicitly activate/focus so it becomes visible and interactive.
    ShowWindow(hwnd, SW_SHOW);
    ShowWindow(hwnd, SW_RESTORE);
    SetWindowPos(hwnd, HWND_TOP, 0, 0, 0, 0,
                 SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW);
    SetForegroundWindow(hwnd);
    SetActiveWindow(hwnd);
    SetFocus(hwnd);
}



// File format:
// Each non-empty non-comment line: appExe|localPath|serverPath
static void LoadRulesFromFile(const std::wstring& filePath) {
    std::string pathUtf8;
    {
        int needed = WideCharToMultiByte(CP_UTF8, 0, filePath.c_str(), -1, nullptr, 0, nullptr, nullptr);
        if (needed <= 0) return;
        pathUtf8.resize((size_t)needed - 1);
        WideCharToMultiByte(CP_UTF8, 0, filePath.c_str(), -1, pathUtf8.data(), needed, nullptr, nullptr);
    }

    std::ifstream in(pathUtf8);
    if (!in) return;

    std::vector<SyncRule> loaded;
    std::string lineA;
    while (std::getline(in, lineA)) {
        if (lineA.empty()) continue;
        if (!lineA.empty() && lineA[0] == '#') continue;

        // Split on '|'
        size_t p1 = lineA.find('|');
        size_t p2 = (p1 == std::string::npos) ? std::string::npos : lineA.find('|', p1 + 1);
        if (p1 == std::string::npos || p2 == std::string::npos) continue;

        std::string a = lineA.substr(0, p1);
        std::string l = lineA.substr(p1 + 1, p2 - (p1 + 1));
        std::string s = lineA.substr(p2 + 1);

        auto toW = [](const std::string& u8) -> std::wstring {
            std::wstring w;
            if (!u8.empty()) {
                int wneeded = MultiByteToWideChar(CP_UTF8, 0, u8.c_str(), (int)u8.size(), nullptr, 0);
                if (wneeded > 0) {
                    w.resize((size_t)wneeded);
                    MultiByteToWideChar(CP_UTF8, 0, u8.c_str(), (int)u8.size(), w.data(), wneeded);
                }
            }
            return w;
        };

        SyncRule r;
        r.appExe = Trim(toW(a));
        r.localPath = Trim(toW(l));
        r.serverPath = Trim(toW(s));
        r.appExeNorm = NormalizePath(r.appExe);

        if (r.appExeNorm.empty() || r.localPath.empty() || r.serverPath.empty()) continue;
        loaded.push_back(r);
    }

    {
        std::lock_guard<std::mutex> lock(g_app.rulesMutex);
        g_app.rules = std::move(loaded);
    }
    ReloadRulesListUIFromState();
}

static void SaveRulesToFile(const std::wstring& filePath) {
    std::string pathUtf8;
    {
        int needed = WideCharToMultiByte(CP_UTF8, 0, filePath.c_str(), -1, nullptr, 0, nullptr, nullptr);
        if (needed <= 0) return;
        pathUtf8.resize((size_t)needed - 1);
        WideCharToMultiByte(CP_UTF8, 0, filePath.c_str(), -1, pathUtf8.data(), needed, nullptr, nullptr);
    }

    std::ofstream out(pathUtf8, std::ios::trunc | std::ios::binary);
    if (!out) return;

    out << "# FileSyncer rules - one rule per line\n";
    out << "# Format: appExe|localPath|serverPath\n";

    std::lock_guard<std::mutex> lock(g_app.rulesMutex);
    for (const auto& r : g_app.rules) {
        auto writeW = [&](const std::wstring& w) {
            if (w.empty()) return;
            int needed = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
            if (needed <= 0) return;
            std::string u8;
            u8.resize((size_t)needed);
            WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), u8.data(), needed, nullptr, nullptr);
            out << u8;
        };

        writeW(r.appExe);
        out << "|";
        writeW(r.localPath);
        out << "|";
        writeW(r.serverPath);
        out << "\n";
    }
}

// --------------------------- Log UI ---------------------------

static void AppendLogLine(const std::wstring& line) {
    if (!g_app.hLogEdit) return;

    // Append to edit control efficiently
    int len = GetWindowTextLengthW(g_app.hLogEdit);
    SendMessageW(g_app.hLogEdit, EM_SETSEL, (WPARAM)len, (LPARAM)len);
    std::wstring withNewline = line + L"\r\n";
    SendMessageW(g_app.hLogEdit, EM_REPLACESEL, FALSE, (LPARAM)withNewline.c_str());

    // Scroll caret into view
    SendMessageW(g_app.hLogEdit, EM_SCROLLCARET, 0, 0);
}

static void UpdateStatusBar() {
    if (!g_app.hStatus) return;

    long s = g_app.startCount.load();
    long t = g_app.stopCount.load();

    int rulesCount = 0;
    {
        std::lock_guard<std::mutex> lock(g_app.rulesMutex);
        rulesCount = (int)g_app.rules.size();
    }

    std::wstringstream ss;
    ss << L"WMI: " << (g_app.wmiActive.load() ? L"active" : L"inactive")
       << L" | Rules: " << rulesCount
       << L" | Starts: " << s
       << L" | Stops: " << t;

    SetWindowTextW(g_app.hStatus, ss.str().c_str());
}

// Custom message payload for WM_APP_LOG
struct LogMessage {
    std::wstring line;
};

// --------------------------- WMI Sink ---------------------------

class EventSink : public IWbemObjectSink {
    std::atomic<long> m_ref{1};
    IWbemServices* m_pSvc = nullptr;
    std::unordered_map<unsigned long, std::wstring> m_pidToExeNorm;
    std::unordered_map<unsigned long, std::wstring> m_pidToExeDisplay;
    std::mutex m_mapMutex;

public:
    explicit EventSink(IWbemServices* svc) : m_pSvc(svc) {
        if (m_pSvc) m_pSvc->AddRef();
    }
    ~EventSink() {
        if (m_pSvc) m_pSvc->Release();
        m_pSvc = nullptr;
    }

    // IUnknown
    STDMETHODIMP QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IWbemObjectSink) {
            *ppv = static_cast<IWbemObjectSink*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }
    STDMETHODIMP_(ULONG) AddRef() override { return (ULONG)++m_ref; }
    STDMETHODIMP_(ULONG) Release() override {
        long v = --m_ref;
        if (v == 0) delete this;
        return (ULONG)v;
    }

    std::wstring ResolveExecutablePath(unsigned long pid) {
        if (!m_pSvc) return L"";

        IEnumWbemClassObject* pEnum = nullptr;
        std::wstring query = L"SELECT ExecutablePath FROM Win32_Process WHERE ProcessId = " + std::to_wstring(pid);
        HRESULT qhr = m_pSvc->ExecQuery(_bstr_t(L"WQL"), _bstr_t(query.c_str()),
                                        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                                        NULL, &pEnum);
        if (SUCCEEDED(qhr) && pEnum) {
            IWbemClassObject* pObj = nullptr;
            ULONG returned = 0;
            if (SUCCEEDED(pEnum->Next(WBEM_INFINITE, 1, &pObj, &returned)) && returned == 1) {
                VARIANT vtPath;
                VariantInit(&vtPath);
                if (SUCCEEDED(pObj->Get(L"ExecutablePath", 0, &vtPath, 0, 0)) &&
                    vtPath.vt == VT_BSTR && vtPath.bstrVal) {
                    std::wstring path = vtPath.bstrVal;
                    VariantClear(&vtPath);
                    pObj->Release();
                    pEnum->Release();
                    return path;
                }
                VariantClear(&vtPath);
                pObj->Release();
            }
            pEnum->Release();
        }
        return L"";
    }

    static void PostUILog(const std::wstring& line) {
        if (!g_app.hwndMain) return;
        auto* msg = new LogMessage();
        msg->line = line;
        PostMessageW(g_app.hwndMain, WM_APP_LOG, 0, (LPARAM)msg);
    }

    static void DoSyncCopy(const std::wstring& direction, const SyncRule& r) {
        // direction: "Server->Local" or "Local->Server"
        SYSTEMTIME st = NowLocalTime();
        std::wstringstream ss;
        ss << L"[" << FormatTimestamp(st) << L"] SYNC   " << direction
           << L"   app=" << r.appExe
           << L"   src=" << ((direction == L"Server->Local") ? r.serverPath : r.localPath)
           << L"   dst=" << ((direction == L"Server->Local") ? r.localPath : r.serverPath);
        PostUILog(ss.str());

        const std::wstring& src = (direction == L"Server->Local") ? r.serverPath : r.localPath;
        const std::wstring& dst = (direction == L"Server->Local") ? r.localPath : r.serverPath;

        if (!PathExistsAny(src)) {
            DWORD gle = GetLastError();

            // If we get "Logon failure" (1326) or "Access denied" (5), try refreshing the share connection
            if (gle == ERROR_LOGON_FAILURE || gle == ERROR_ACCESS_DENIED) {
                RefreshNetworkShareConnection(src);
                // Check again
                if (PathExistsAny(src)) {
                    gle = 0; // Recovered
                } else {
                    gle = GetLastError(); // Still failing
                }
            }

            if (gle != 0) {
                // Capture the last error from the failing GetFileAttributesW
                wchar_t msgbuf[512] = {0};
                FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                               nullptr, gle, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                               msgbuf, (DWORD)_countof(msgbuf), nullptr);

                SYSTEMTIME st2 = NowLocalTime();
                std::wstringstream errss;
                errss << L"[" << FormatTimestamp(st2) << L"] ERROR  Source does not exist: " << src
                      << L"  (GetFileAttributesW error=" << gle << L", msg=\"" << msgbuf << L"\")";
                PostUILog(errss.str());
                return;
            }
        }

        bool ok = SyncCopyPath(src, dst);
        SYSTEMTIME st3 = NowLocalTime();
        std::wstringstream done;
        done << L"[" << FormatTimestamp(st3) << L"] SYNC   " << (ok ? L"OK" : L"FAILED");
        PostUILog(done.str());
    }

    STDMETHODIMP Indicate(long lObjectCount, IWbemClassObject** apObjArray) override {
        for (long i = 0; i < lObjectCount; ++i) {
            VARIANT vtClass, vtPid;
            VariantInit(&vtClass);
            VariantInit(&vtPid);

            std::wstring className;
            if (SUCCEEDED(apObjArray[i]->Get(L"__CLASS", 0, &vtClass, 0, 0)) && vtClass.vt == VT_BSTR && vtClass.bstrVal) {
                className = vtClass.bstrVal;
            }

            unsigned long pid = 0;
            if (SUCCEEDED(apObjArray[i]->Get(L"ProcessID", 0, &vtPid, 0, 0))) {
                if (vtPid.vt == VT_I4 || vtPid.vt == VT_UI4 || vtPid.vt == VT_I2) {
                    pid = (unsigned long)vtPid.ulVal;
                }
            }

            if (pid == 0) {
                VariantClear(&vtClass);
                VariantClear(&vtPid);
                continue;
            }

            if (className == L"Win32_ProcessStartTrace") {
                g_app.startCount.fetch_add(1);

                std::wstring exe = ResolveExecutablePath(pid);
                if (!exe.empty()) {
                    std::wstring exeNorm = NormalizePath(exe);

                    {
                        std::lock_guard<std::mutex> lock(m_mapMutex);
                        m_pidToExeNorm[pid] = exeNorm;
                        m_pidToExeDisplay[pid] = exe;
                    }

                    std::vector<SyncRule> matches;
                    {
                        std::lock_guard<std::mutex> lock(g_app.rulesMutex);
                        for (const auto& r : g_app.rules) {
                            if (r.appExeNorm == exeNorm) matches.push_back(r);
                        }
                    }
                    if (!matches.empty()) {
                        SYSTEMTIME st = NowLocalTime();
                        std::wstringstream ss;
                        ss << L"[" << FormatTimestamp(st) << L"] START  " << exe << L"  (PID " << pid << L")";
                        PostUILog(ss.str());
                        for (const auto& rule : matches) DoSyncCopy(L"Server->Local", rule);
                    }
                }
            } else if (className == L"Win32_ProcessStopTrace") {
                g_app.stopCount.fetch_add(1);

                std::wstring exeNorm;
                std::wstring exeDisp;

                {
                    std::lock_guard<std::mutex> lock(m_mapMutex);
                    auto itN = m_pidToExeNorm.find(pid);
                    auto itD = m_pidToExeDisplay.find(pid);
                    if (itN != m_pidToExeNorm.end()) exeNorm = itN->second;
                    if (itD != m_pidToExeDisplay.end()) exeDisp = itD->second;

                    if (itN != m_pidToExeNorm.end()) m_pidToExeNorm.erase(itN);
                    if (itD != m_pidToExeDisplay.end()) m_pidToExeDisplay.erase(itD);
                }

                if (!exeNorm.empty()) {
                    std::vector<SyncRule> matches;
                    {
                        std::lock_guard<std::mutex> lock(g_app.rulesMutex);
                        for (const auto& r : g_app.rules) {
                            if (r.appExeNorm == exeNorm) matches.push_back(r);
                        }
                    }
                    if (!matches.empty()) {
                        SYSTEMTIME st = NowLocalTime();
                        std::wstringstream ss;
                        ss << L"[" << FormatTimestamp(st) << L"] STOP   " << exeDisp << L"  (PID " << pid << L")";
                        PostUILog(ss.str());
                        for (const auto& rule : matches) DoSyncCopy(L"Local->Server", rule);
                    }
                }
            }

            VariantClear(&vtClass);
            VariantClear(&vtPid);
        }

        PostMessageW(g_app.hwndMain, WM_APP_COUNTS, 0, 0);
        return S_OK;
    }

    STDMETHODIMP SetStatus(long lFlags, HRESULT hResult, BSTR, IWbemClassObject*) override {
        // Post status to UI log (filtered by nothing, because it's app status)
        _com_error err(hResult);
        std::wstring msg = err.ErrorMessage() ? (const wchar_t*)_bstr_t(err.ErrorMessage()) : L"<no message>";

        std::wstringstream ss;
        ss << L"[WMI] Status flags=" << lFlags << L" hResult=0x" << std::hex << (unsigned long)hResult << std::dec
           << L" (" << msg << L")";
        PostUILog(ss.str());

        return S_OK;
    }
};

// --------------------------- WMI Setup/Teardown ---------------------------

static void WmiTeardown() {
    g_app.wmiActive = false;

    if (g_app.pSvc && g_app.pSinkUnk) {
        // Best-effort cancel
        g_app.pSvc->CancelAsyncCall((IWbemObjectSink*)g_app.pSinkUnk);
    }

    if (g_app.pSinkUnk) {
        g_app.pSinkUnk->Release();
        g_app.pSinkUnk = nullptr;
    }
    if (g_app.pSvc) {
        g_app.pSvc->Release();
        g_app.pSvc = nullptr;
    }
    if (g_app.pLoc) {
        g_app.pLoc->Release();
        g_app.pLoc = nullptr;
    }

    CoUninitialize();
}

static bool WmiInit() {
    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(hr)) {
        AppendLogLine(L"[WMI] CoInitializeEx failed");
        return false;
    }

    hr = CoInitializeSecurity(
        NULL,
        -1,
        NULL,
        NULL,
        RPC_C_AUTHN_LEVEL_DEFAULT,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        EOAC_NONE,
        NULL
    );
    // If already initialized by someone else in process, this can be RPC_E_TOO_LATE.
    if (FAILED(hr) && hr != RPC_E_TOO_LATE) {
        AppendLogLine(L"[WMI] CoInitializeSecurity failed");
        CoUninitialize();
        return false;
    }

    hr = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER,
                          IID_IWbemLocator, (LPVOID*)&g_app.pLoc);
    if (FAILED(hr) || !g_app.pLoc) {
        AppendLogLine(L"[WMI] CoCreateInstance(WbemLocator) failed");
        CoUninitialize();
        return false;
    }

    hr = g_app.pLoc->ConnectServer(
        _bstr_t(L"ROOT\\CIMV2"),
        NULL, NULL, NULL,
        0, NULL, NULL,
        &g_app.pSvc
    );
    if (FAILED(hr) || !g_app.pSvc) {
        AppendLogLine(L"[WMI] ConnectServer failed");
        g_app.pLoc->Release(); g_app.pLoc = nullptr;
        CoUninitialize();
        return false;
    }

    hr = CoSetProxyBlanket(
        g_app.pSvc,
        RPC_C_AUTHN_WINNT,
        RPC_C_AUTHZ_NONE,
        NULL,
        RPC_C_AUTHN_LEVEL_CALL,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        EOAC_NONE
    );
    if (FAILED(hr)) {
        AppendLogLine(L"[WMI] CoSetProxyBlanket failed");
        g_app.pSvc->Release(); g_app.pSvc = nullptr;
        g_app.pLoc->Release(); g_app.pLoc = nullptr;
        CoUninitialize();
        return false;
    }

    // Create sink
    EventSink* sink = new EventSink(g_app.pSvc);
    g_app.pSinkUnk = sink; // refcount = 1

    // Subscribe start
    hr = g_app.pSvc->ExecNotificationQueryAsync(
        _bstr_t(L"WQL"),
        _bstr_t(L"SELECT * FROM Win32_ProcessStartTrace"),
        WBEM_FLAG_SEND_STATUS,
        NULL,
        (IWbemObjectSink*)g_app.pSinkUnk
    );
    if (FAILED(hr)) {
        AppendLogLine(L"[WMI] ExecNotificationQueryAsync(start) failed");
        WmiTeardown();
        return false;
    }

    // Subscribe stop
    hr = g_app.pSvc->ExecNotificationQueryAsync(
        _bstr_t(L"WQL"),
        _bstr_t(L"SELECT * FROM Win32_ProcessStopTrace"),
        WBEM_FLAG_SEND_STATUS,
        NULL,
        (IWbemObjectSink*)g_app.pSinkUnk
    );
    if (FAILED(hr)) {
        AppendLogLine(L"[WMI] ExecNotificationQueryAsync(stop) failed");
        WmiTeardown();
        return false;
    }

    g_app.wmiActive = true;
    AppendLogLine(L"[WMI] Subscriptions active. Only filtered executable paths will be logged.");
    UpdateStatusBar();
    return true;
}

// --------------------------- Layout ---------------------------

static void CreateControls(HWND hwnd) {
    // Basic font
    HFONT hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);

    // Three edit boxes for rule creation
    g_app.hAppEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
        10, 10, 300, 24, hwnd, (HMENU)IDC_APP_EDIT, GetModuleHandleW(nullptr), nullptr);

    g_app.hLocalEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
        320, 10, 280, 24, hwnd, (HMENU)IDC_LOCAL_EDIT, GetModuleHandleW(nullptr), nullptr);

    g_app.hServerEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
        610, 10, 280, 24, hwnd, (HMENU)IDC_SERVER_EDIT, GetModuleHandleW(nullptr), nullptr);

    g_app.hAddBtn = CreateWindowExW(0, L"BUTTON", L"Add/Update",
        WS_CHILD | WS_VISIBLE,
        900, 10, 110, 24, hwnd, (HMENU)IDC_ADD_BTN, GetModuleHandleW(nullptr), nullptr);

    g_app.hRemoveBtn = CreateWindowExW(0, L"BUTTON", L"Remove",
        WS_CHILD | WS_VISIBLE,
        1020, 10, 80, 24, hwnd, (HMENU)IDC_REMOVE_BTN, GetModuleHandleW(nullptr), nullptr);

    g_app.hClearBtn = CreateWindowExW(0, L"BUTTON", L"Clear",
        WS_CHILD | WS_VISIBLE,
        1110, 10, 80, 24, hwnd, (HMENU)IDC_CLEAR_BTN, GetModuleHandleW(nullptr), nullptr);

    g_app.hLoadBtn = CreateWindowExW(0, L"BUTTON", L"Load",
        WS_CHILD | WS_VISIBLE,
        1200, 10, 80, 24, hwnd, (HMENU)IDC_LOAD_BTN, GetModuleHandleW(nullptr), nullptr);

    g_app.hSaveBtn = CreateWindowExW(0, L"BUTTON", L"Save",
        WS_CHILD | WS_VISIBLE,
        1290, 10, 80, 24, hwnd, (HMENU)IDC_SAVE_BTN, GetModuleHandleW(nullptr), nullptr);

    g_app.hRulesList = CreateWindowExW(WS_EX_CLIENTEDGE, L"LISTBOX", L"",
        WS_CHILD | WS_VISIBLE | LBS_NOTIFY | WS_VSCROLL,
        10, 44, 560, 200, hwnd, (HMENU)IDC_RULES_LIST, GetModuleHandleW(nullptr), nullptr);

    // Log on the right
    g_app.hLogEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY | WS_VSCROLL,
        580, 44, 520, 500, hwnd, (HMENU)IDC_LOG_EDIT, GetModuleHandleW(nullptr), nullptr);

    g_app.hLogClear = CreateWindowExW(0, L"BUTTON", L"Clear Log",
        WS_CHILD | WS_VISIBLE,
        10, 250, 120, 26, hwnd, (HMENU)IDC_LOG_CLEAR_BTN, GetModuleHandleW(nullptr), nullptr);

    g_app.hLogCopy = CreateWindowExW(0, L"BUTTON", L"Copy Log",
        WS_CHILD | WS_VISIBLE,
        140, 250, 120, 26, hwnd, (HMENU)IDC_LOG_COPY_BTN, GetModuleHandleW(nullptr), nullptr);

    g_app.hStatus = CreateWindowExW(WS_EX_CLIENTEDGE, L"STATIC", L"",
        WS_CHILD | WS_VISIBLE,
        10, 284, 1090, 22, hwnd, (HMENU)IDC_STATUS, GetModuleHandleW(nullptr), nullptr);

    // Set fonts
    HWND ctrls[] = {
        g_app.hAppEdit, g_app.hLocalEdit, g_app.hServerEdit,
        g_app.hAddBtn, g_app.hRemoveBtn, g_app.hClearBtn, g_app.hLoadBtn, g_app.hSaveBtn,
        g_app.hRulesList,
        g_app.hLogEdit, g_app.hLogClear, g_app.hLogCopy, g_app.hStatus
    };
    for (HWND c : ctrls) {
        SendMessageW(c, WM_SETFONT, (WPARAM)hFont, TRUE);
    }

    SetWindowTextW(g_app.hAppEdit, L"C:\\Path\\To\\App.exe");
    SetWindowTextW(g_app.hLocalEdit, L"C:\\Local\\FolderOrFile");
    SetWindowTextW(g_app.hServerEdit, L"\\\\server\\share\\FolderOrFile");
    UpdateStatusBar();
}

static void DoLayout(HWND hwnd) {
    RECT rc;
    GetClientRect(hwnd, &rc);

    int margin = 10;
    int top = margin;
    int editH = 24;
    int btnH = 24;
    int btnW = 80;
    int gap = 10;

    int width = rc.right - rc.left;
    int height = rc.bottom - rc.top;

    int filterEditW = width - (margin * 2) - (btnW * 5) - (gap * 5);
    if (filterEditW < 200) filterEditW = 200;

    int x = margin;

    // Top row: App / Local / Server edits, then action buttons
    // Use fixed widths that adapt to window size.
    int editsGap = gap;
    int buttonsTotalW = 110 + gap + btnW * 4 + gap * 3; // Add/Update is 110, then Remove/Clear/Load/Save
    int editsTotalW = width - (margin * 2) - buttonsTotalW - editsGap * 2;
    if (editsTotalW < 600) editsTotalW = 600;

    int appW = editsTotalW / 3;
    int localW = editsTotalW / 3;
    int serverW = editsTotalW - appW - localW;

    MoveWindow(g_app.hAppEdit, x, top, appW, editH, TRUE);
    x += appW + editsGap;

    MoveWindow(g_app.hLocalEdit, x, top, localW, editH, TRUE);
    x += localW + editsGap;

    MoveWindow(g_app.hServerEdit, x, top, serverW, editH, TRUE);
    x += serverW + gap;

    MoveWindow(g_app.hAddBtn, x, top, 110, btnH, TRUE); x += 110 + gap;
    MoveWindow(g_app.hRemoveBtn, x, top, btnW, btnH, TRUE); x += btnW + gap;
    MoveWindow(g_app.hClearBtn, x, top, btnW, btnH, TRUE); x += btnW + gap;
    MoveWindow(g_app.hLoadBtn, x, top, btnW, btnH, TRUE); x += btnW + gap;
    MoveWindow(g_app.hSaveBtn, x, top, btnW, btnH, TRUE);

    int contentTop = top + editH + gap;
    int statusH = 22;
    int bottomControlsH = 26;

    int availableH = height - contentTop - margin - statusH - gap - bottomControlsH - gap;
    if (availableH < 100) availableH = 100;

    // Left panel dimensions (rules list)
    int leftW = 560;
    if (leftW > width - margin * 3 - 240) leftW = width - margin * 3 - 240;
    if (leftW < 320) leftW = 320;

    MoveWindow(g_app.hRulesList, margin, contentTop, leftW, availableH, TRUE);

    // Bottom buttons under list
    int bottomY = contentTop + availableH + gap;
    MoveWindow(g_app.hLogClear, margin, bottomY, 120, bottomControlsH, TRUE);
    MoveWindow(g_app.hLogCopy, margin + 130, bottomY, 120, bottomControlsH, TRUE);

    // Status bar at bottom
    int statusY = bottomY + bottomControlsH + gap;
    MoveWindow(g_app.hStatus, margin, statusY, width - margin * 2, statusH, TRUE);

    // Log edit occupies rest to the right of list
    int logX = margin + leftW + gap;
    int logW = width - logX - margin;
    int logH = statusY - contentTop - gap;
    if (logW < 240) logW = 240;
    if (logH < 100) logH = 100;

    MoveWindow(g_app.hLogEdit, logX, contentTop, logW, logH, TRUE);
}

// --------------------------- Commands ---------------------------

static std::wstring GetWindowTextString(HWND h) {
    int len = GetWindowTextLengthW(h);
    std::wstring s;
    s.resize((size_t)len);
    if (len > 0) {
        GetWindowTextW(h, s.data(), len + 1);
    }
    return s;
}

static void HandleAddRule() {
    std::wstring app = Trim(GetWindowTextString(g_app.hAppEdit));
    std::wstring local = Trim(GetWindowTextString(g_app.hLocalEdit));
    std::wstring server = Trim(GetWindowTextString(g_app.hServerEdit));
    if (app.empty() || local.empty() || server.empty()) return;

    AddRule(app, local, server);
    AppendLogLine(L"[UI] Rule added/updated.");
    UpdateStatusBar();
}

static void HandleLoadRules() {
    std::wstring file = DefaultRulesFilePath();
    LoadRulesFromFile(file);
    AppendLogLine(L"[UI] Loaded rules from: " + file);
    UpdateStatusBar();
}

static void HandleSaveRules() {
    std::wstring file = DefaultRulesFilePath();
    SaveRulesToFile(file);
    AppendLogLine(L"[UI] Saved rules to: " + file);
    UpdateStatusBar();
}

static void HandleCopyLog() {
    int len = GetWindowTextLengthW(g_app.hLogEdit);
    if (len <= 0) return;
    std::wstring text;
    text.resize((size_t)len);
    GetWindowTextW(g_app.hLogEdit, text.data(), len + 1);
    SetClipboardText(g_app.hwndMain, text);
    AppendLogLine(L"[UI] Log copied to clipboard.");
}

static void HandleClearLog() {
    SetWindowTextW(g_app.hLogEdit, L"");
    AppendLogLine(L"[UI] Log cleared.");
}

// --------------------------- Window Proc ---------------------------

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE: {
            g_app.hwndMain = hwnd;
            CreateControls(hwnd);
            DoLayout(hwnd);

            // Load rules if present (best effort)
            LoadRulesFromFile(DefaultRulesFilePath());

            // Start WMI
            WmiInit();

            // Add tray icon (so close/minimize can hide instead of exit)
            TrayAddOrUpdate(hwnd);

            // Start hidden in the system tray
            HideToTray(hwnd);

            // Periodic status updates
            SetTimer(hwnd, TIMER_HEARTBEAT, 500, nullptr);
            return 0;
        }

        case WM_SIZE: {
            DoLayout(hwnd);

            // Optional: minimize-to-tray when user minimizes
            if (wParam == SIZE_MINIMIZED) {
                HideToTray(hwnd);
            }
            return 0;
        }

        case WM_TIMER: {
            if (wParam == TIMER_HEARTBEAT) {
                UpdateStatusBar();
            }
            return 0;
        }

        case WM_COMMAND: {
            int id = LOWORD(wParam);
            int code = HIWORD(wParam);

            if (id == IDC_ADD_BTN && code == BN_CLICKED) {
                HandleAddRule();
                return 0;
            }
            if (id == IDC_REMOVE_BTN && code == BN_CLICKED) {
                RemoveSelectedRule();
                UpdateStatusBar();
                return 0;
            }
            if (id == IDC_CLEAR_BTN && code == BN_CLICKED) {
                ClearRules();
                UpdateStatusBar();
                return 0;
            }
            if (id == IDC_LOAD_BTN && code == BN_CLICKED) {
                HandleLoadRules();
                return 0;
            }
            if (id == IDC_SAVE_BTN && code == BN_CLICKED) {
                HandleSaveRules();
                return 0;
            }
            if (id == IDC_LOG_COPY_BTN && code == BN_CLICKED) {
                HandleCopyLog();
                return 0;
            }
            if (id == IDC_LOG_CLEAR_BTN && code == BN_CLICKED) {
                HandleClearLog();
                return 0;
            }

            // Tray menu commands
            if (id == ID_TRAY_RESTORE) {
                RestoreFromTray(hwnd);
                return 0;
            }
            if (id == ID_TRAY_EXIT) {
                g_app.allowExit = true;
                DestroyWindow(hwnd);
                return 0;
            }

            // Double-click on list removes
            if (id == IDC_RULES_LIST && code == LBN_DBLCLK) {
                RemoveSelectedRule();
                UpdateStatusBar();
                return 0;
            }

            return 0;
        }

        case WM_APP_TRAY: {
            // Restore on double-click, show menu on right-click
            if (lParam == WM_LBUTTONDBLCLK) {
                RestoreFromTray(hwnd);
                return 0;
            }
            if (lParam == WM_RBUTTONUP || lParam == WM_CONTEXTMENU) {
                POINT pt;
                GetCursorPos(&pt);

                HMENU menu = CreatePopupMenu();
                if (menu) {
                    InsertMenuW(menu, -1, MF_BYPOSITION, ID_TRAY_RESTORE, L"Restore");
                    InsertMenuW(menu, -1, MF_BYPOSITION, ID_TRAY_EXIT, L"Exit");

                    // Required for the menu to dismiss correctly
                    SetForegroundWindow(hwnd);
                    TrackPopupMenu(menu, TPM_RIGHTBUTTON | TPM_BOTTOMALIGN | TPM_LEFTALIGN, pt.x, pt.y, 0, hwnd, nullptr);
                    DestroyMenu(menu);
                }
                return 0;
            }
            return 0;
        }

        case WM_APP_LOG: {
            auto* lm = (LogMessage*)lParam;
            if (lm) {
                AppendLogLine(lm->line);
                delete lm;
            }
            return 0;
        }

        case WM_APP_COUNTS: {
            UpdateStatusBar();
            return 0;
        }

        case WM_CLOSE: {
            // Close button hides to tray unless user chose Exit from tray menu.
            if (!g_app.allowExit) {
                HideToTray(hwnd);
                return 0;
            }
            DestroyWindow(hwnd);
            return 0;
        }

        case WM_DESTROY: {
            KillTimer(hwnd, TIMER_HEARTBEAT);
            TrayRemove();
            WmiTeardown();
            PostQuitMessage(0);
            return 0;
        }

        default:
            return DefWindowProcW(hwnd, msg, wParam, lParam);
    }
}

// Subclass the three edit boxes so Enter triggers Add/Update
static WNDPROC g_prevAppEditProc = nullptr;
static WNDPROC g_prevLocalEditProc = nullptr;
static WNDPROC g_prevServerEditProc = nullptr;

static LRESULT CALLBACK RuleEditProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (msg == WM_KEYDOWN && wParam == VK_RETURN) {
        HandleAddRule();
        return 0;
    }

    WNDPROC prev = nullptr;
    if (hwnd == g_app.hAppEdit) prev = g_prevAppEditProc;
    else if (hwnd == g_app.hLocalEdit) prev = g_prevLocalEditProc;
    else if (hwnd == g_app.hServerEdit) prev = g_prevServerEditProc;

    return CallWindowProcW(prev ? prev : DefWindowProcW, hwnd, msg, wParam, lParam);
}

// --------------------------- WinMain ---------------------------

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, PWSTR, int nCmdShow) {
    // Initialize common controls (not strictly necessary for basic EDIT/LISTBOX/BUTTON)
    INITCOMMONCONTROLSEX icc{};
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&icc);

    const wchar_t* kClassName = L"FileSyncerGuiMainWindow";

    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = kClassName;

    if (!RegisterClassExW(&wc)) {
        MessageBoxW(nullptr, L"Failed to register window class.", L"FileSyncer", MB_ICONERROR | MB_OK);
        return 1;
    }

    HWND hwnd = CreateWindowExW(
        0,
        kClassName,
        L"FileSyncer - Process Logger (Filtered Paths)",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT,
        920, 560,
        nullptr, nullptr, hInst, nullptr
    );

    if (!hwnd) {
        MessageBoxW(nullptr, L"Failed to create main window.", L"FileSyncer", MB_ICONERROR | MB_OK);
        return 1;
    }

    // Start hidden to tray: never show the window on startup.
    ShowWindow(hwnd, SW_HIDE);
    UpdateWindow(hwnd);

    // After controls are created in WM_CREATE, subclass filter edit
    // (We can do it here too, after the message loop starts, but this is fine.)
    // We need to wait until WM_CREATE has run; do a quick peek.
    MSG msg;
    while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    if (g_app.hAppEdit) {
        g_prevAppEditProc = (WNDPROC)SetWindowLongPtrW(g_app.hAppEdit, GWLP_WNDPROC, (LONG_PTR)RuleEditProc);
    }
    if (g_app.hLocalEdit) {
        g_prevLocalEditProc = (WNDPROC)SetWindowLongPtrW(g_app.hLocalEdit, GWLP_WNDPROC, (LONG_PTR)RuleEditProc);
    }
    if (g_app.hServerEdit) {
        g_prevServerEditProc = (WNDPROC)SetWindowLongPtrW(g_app.hServerEdit, GWLP_WNDPROC, (LONG_PTR)RuleEditProc);
    }

    // Message loop
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    return (int)msg.wParam;
}
