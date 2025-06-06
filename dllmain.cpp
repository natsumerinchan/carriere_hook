#include <windows.h>
#include "detours/detours.h"
#include <shlwapi.h>
#include <string>
#include <fstream>
#include <mutex>
#include <vector>

// 导出函数声明
extern "C" __declspec(dllexport) void StartHook();

// 日志全局变量
std::ofstream logFile;  // 改为普通ofstream
std::mutex logMutex;

// 辅助函数：宽字符串转换为UTF-8
std::string WideToUTF8(const wchar_t* wstr) {
    int utf8Size = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, nullptr, 0, nullptr, nullptr);
    if (utf8Size == 0) return "";
    
    std::vector<char> buffer(utf8Size);
    WideCharToMultiByte(CP_UTF8, 0, wstr, -1, buffer.data(), utf8Size, nullptr, nullptr);
    return std::string(buffer.data(), buffer.size() - 1); // 去掉null终止符
}

// 初始化日志文件
void InitLogFile() {
    wchar_t logFilePath[MAX_PATH];
    GetCurrentDirectoryW(MAX_PATH, logFilePath);
    PathAppendW(logFilePath, L"carriere_hook.log");
    
    // 每次启动覆盖日志而不是追加
    logFile.open(logFilePath, std::ios::out | std::ios::trunc | std::ios::binary);
    if (logFile.is_open()) {
        // 写入UTF-8 BOM
        const unsigned char bom[] = {0xEF, 0xBB, 0xBF};
        logFile.write(reinterpret_cast<const char*>(bom), sizeof(bom));
        
        // 写入初始日志并刷新
        logFile << WideToUTF8(L"===== Hook DLL 已加载 =====\r\n");
        logFile.flush();  // 确保日志实时写入
    }
}

// #pragma comment(lib, "detours.lib")
#pragma comment(lib, "shlwapi.lib")

// 原始函数指针
static HANDLE (WINAPI * TrueCreateFileA)(
    LPCSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile) = CreateFileA;

// 钩子函数
HANDLE WINAPI HookedCreateFileA(
    LPCSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile)
{
    // 转换ANSI路径为宽字符
    int wlen = MultiByteToWideChar(CP_ACP, 0, lpFileName, -1, NULL, 0);
    wchar_t* wpath = new wchar_t[wlen];
    MultiByteToWideChar(CP_ACP, 0, lpFileName, -1, wpath, wlen);
    
    // 检查路径是否包含"save"（不区分大小写）
    if (StrStrIA(lpFileName, "save/") != nullptr) {
        // 记录跳过重定向
        if (logFile.is_open()) {
            wchar_t buffer[512];
            swprintf_s(buffer, L"跳过重定向（存档文件）: %s\r\n", wpath);
            logFile << WideToUTF8(buffer);
            logFile.flush();
        }
        HANDLE hFile = TrueCreateFileA(lpFileName, dwDesiredAccess, dwShareMode,
                                      lpSecurityAttributes, dwCreationDisposition,
                                      dwFlagsAndAttributes, hTemplateFile);
        delete[] wpath;
        return hFile;
    }
    
    // 提取纯文件名（忽略任何路径结构）
    wchar_t filename[MAX_PATH];
    wchar_t* lastBackslash = wcsrchr(wpath, L'\\');
    wchar_t* lastSlash = wcsrchr(wpath, L'/');
    wchar_t* lastSeparator = lastBackslash ? lastBackslash : lastSlash;
    if (lastSeparator) {
        wcscpy_s(filename, MAX_PATH, lastSeparator + 1);
    } else {
        wcscpy_s(filename, MAX_PATH, wpath);
    }
    
    // 构建CHS_DATA路径
    wchar_t newPath[MAX_PATH];
    GetCurrentDirectoryW(MAX_PATH, newPath);
    PathCombineW(newPath, newPath, L"CHS_DATA");
    PathCombineW(newPath, newPath, filename);
    
    // 使用CreateFileW打开CHS_DATA中的文件
    HANDLE hFile = CreateFileW(
        newPath,
        dwDesiredAccess, 
        dwShareMode,
        lpSecurityAttributes,
        dwCreationDisposition,
        dwFlagsAndAttributes,
        hTemplateFile);
    
    if (hFile != INVALID_HANDLE_VALUE) {
        // 记录重定向成功并实时刷新
        if (logFile.is_open()) {
            wchar_t buffer[512];
            swprintf_s(buffer, L"重定向成功: %s (句柄: %p)\r\n", newPath, hFile);
            logFile << WideToUTF8(buffer);
            logFile.flush();  // 确保日志实时写入
        }
        delete[] wpath;
        return hFile;
    }
    
    // 只记录非文件不存在的错误，并实时刷新
    if (logFile.is_open()) {
        DWORD error = GetLastError();
        if (error != ERROR_FILE_NOT_FOUND) {
            wchar_t buffer[512];
            if (error == ERROR_PATH_NOT_FOUND) {
                swprintf_s(buffer, L"CHS_DATA路径不存在: %s (错误代码: %lu)\r\n", 
                          newPath, error);
            } else {
                swprintf_s(buffer, L"重定向失败: %s (错误代码: %lu)\r\n", 
                          newPath, error);
            }
            logFile << WideToUTF8(buffer);
            logFile.flush();  // 确保日志实时写入
        }
    }
    
    // 回退原始路径（使用原始ANSI调用）
    delete[] wpath;
    return TrueCreateFileA(lpFileName, dwDesiredAccess, dwShareMode,
                          lpSecurityAttributes, dwCreationDisposition,
                          dwFlagsAndAttributes, hTemplateFile);
}

// 原始CreateFontA函数指针
static HFONT (WINAPI * TrueCreateFontA)(
    int nHeight,
    int nWidth,
    int nEscapement,
    int nOrientation,
    int fnWeight,
    DWORD fdwItalic,
    DWORD fdwUnderline,
    DWORD fdwStrikeOut,
    DWORD fdwCharSet,
    DWORD fdwOutputPrecision,
    DWORD fdwClipPrecision,
    DWORD fdwQuality,
    DWORD fdwPitchAndFamily,
    LPCSTR lpszFace) = CreateFontA;

// CreateFontA钩子函数
HFONT WINAPI HookedCreateFontA(
    int nHeight,
    int nWidth,
    int nEscapement,
    int nOrientation,
    int fnWeight,
    DWORD fdwItalic,
    DWORD fdwUnderline,
    DWORD fdwStrikeOut,
    DWORD fdwCharSet,
    DWORD fdwOutputPrecision,
    DWORD fdwClipPrecision,
    DWORD fdwQuality,
    DWORD fdwPitchAndFamily,
    LPCSTR lpszFace)
{
    // 强制使用0x80字符集(SHIFTJIS_CHARSET)
    fdwCharSet = 0x80;
    
    // 转换为宽字符字体名"VL ゴシック"
    return CreateFontW(
        nHeight,
        nWidth,
        nEscapement,
        nOrientation,
        fnWeight,
        fdwItalic,
        fdwUnderline,
        fdwStrikeOut,
        fdwCharSet,
        fdwOutputPrecision,
        fdwClipPrecision,
        fdwQuality,
        fdwPitchAndFamily,
        L"VL ゴシック");
}

// Detours入口点
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved)
{
    if (reason == DLL_PROCESS_ATTACH) {
        // 初始化日志系统
        InitLogFile();
        
        DetourRestoreAfterWith();
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)TrueCreateFileA, HookedCreateFileA);
        DetourAttach(&(PVOID&)TrueCreateFontA, HookedCreateFontA);
        DetourTransactionCommit();
        
        // 记录加载成功并刷新
        if (logFile.is_open()) {
            logFile << WideToUTF8(L"Carriere Hook 已安装成功\r\n");
            logFile.flush();  // 确保日志实时写入
        }
    }
    else if (reason == DLL_PROCESS_DETACH) {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach(&(PVOID&)TrueCreateFileA, HookedCreateFileA);
        DetourDetach(&(PVOID&)TrueCreateFontA, HookedCreateFontA);
        DetourTransactionCommit();
    }
    
    return TRUE;
}

// 导出函数实现
extern "C" __declspec(dllexport) void StartHook() {
    // 此函数仅用于导出，实际工作已在DllMain中完成
    // 用户可以使用CFF Explorer将入口点修改为此函数
}
