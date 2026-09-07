#include <Windows.h>
#include <CommCtrl.h>
#include <string>
#include <thread>
#include <chrono>
#include <fstream>
#include <TlHelp32.h>
#include <cstdio>
#include "offsets.hpp"

#pragma comment(lib, "Comctl32.lib")
#pragma comment(linker, "/SUBSYSTEM:WINDOWS")
#pragma comment(linker, "\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

HWND g_hEditScript = NULL;
HWND g_hEditLog = NULL;
HWND g_hBtnInject = NULL;
HWND g_hBtnExecute = NULL;
HWND g_hStatus = NULL;

DWORD g_pid = 0;
HANDLE g_hProcess = NULL;
void* g_mappedDLL = NULL;

void LogToUI(const std::string& msg) {
    if (g_hEditLog) {
        std::string logMsg = "[*] " + msg + "\r\n";
        int len = GetWindowTextLengthA(g_hEditLog);
        SendMessageA(g_hEditLog, EM_SETSEL, len, len);
        SendMessageA(g_hEditLog, EM_REPLACESEL, FALSE, (LPARAM)logMsg.c_str());
    }
}

DWORD GetPid(const std::wstring& name) {
    DWORD pid = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W entry = { sizeof(PROCESSENTRY32W) };
    if (Process32FirstW(snap, &entry)) {
        do {
            if (name == entry.szExeFile) {
                pid = entry.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &entry));
    }
    CloseHandle(snap);
    return pid;
}

// ===== DYNAMIC SYSCALL STUB GENERATOR =====
typedef NTSTATUS(NTAPI* pNtCreateThreadEx)(PHANDLE, ACCESS_MASK, LPVOID, HANDLE, LPTHREAD_START_ROUTINE, LPVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, LPVOID);

pNtCreateThreadEx CreateSyscallStub(DWORD syscallIndex) {
    // Allocate executable memory
    BYTE* stub = (BYTE*)VirtualAlloc(NULL, 32, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!stub) return NULL;

    // mov r10, rcx
    stub[0] = 0x4C;
    stub[1] = 0x8B;
    stub[2] = 0xD1;
    // mov eax, syscallIndex
    stub[3] = 0xB8;
    *(DWORD*)(stub + 4) = syscallIndex;
    // syscall
    stub[8] = 0x0F;
    stub[9] = 0x05;
    // ret
    stub[10] = 0xC3;

    return (pNtCreateThreadEx)stub;
}

// ===== GET SYSCALL NUMBER FROM NTDLL =====
DWORD GetSyscallIndex() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return 0;
    FARPROC pFunc = GetProcAddress(ntdll, "NtCreateThreadEx");
    if (!pFunc) return 0;
    // Look for mov eax, imm32; syscall; ret
    BYTE* bytes = (BYTE*)pFunc;
    for (int i = 0; i < 64; i++) {
        if (bytes[i] == 0xB8 && bytes[i + 5] == 0x0F && bytes[i + 6] == 0x05 && bytes[i + 7] == 0xC3) {
            return *(DWORD*)(bytes + i + 1);
        }
    }
    return 0; // fallback – use known index for Windows 10/11
}

// ===== MANUAL MAP DLL =====
void* ManualMapDLL(const std::string& dllPath) {
    HANDLE hFile = CreateFileA(dllPath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return NULL;

    DWORD fileSize = GetFileSize(hFile, NULL);
    BYTE* fileData = new BYTE[fileSize];
    DWORD bytesRead;
    ReadFile(hFile, fileData, fileSize, &bytesRead, NULL);
    CloseHandle(hFile);

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileData;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(fileData + dosHeader->e_lfanew);

    SIZE_T imageSize = ntHeaders->OptionalHeader.SizeOfImage;
    LPVOID imageBase = VirtualAllocEx(g_hProcess, (LPVOID)ntHeaders->OptionalHeader.ImageBase, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!imageBase) {
        imageBase = VirtualAllocEx(g_hProcess, NULL, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!imageBase) {
            delete[] fileData;
            return NULL;
        }
    }

    WriteProcessMemory(g_hProcess, imageBase, fileData, ntHeaders->OptionalHeader.SizeOfHeaders, NULL);

    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, section++) {
        if (section->SizeOfRawData) {
            LPVOID dest = (BYTE*)imageBase + section->VirtualAddress;
            WriteProcessMemory(g_hProcess, dest, fileData + section->PointerToRawData, section->SizeOfRawData, NULL);
        }
    }

    if (imageBase != (LPVOID)ntHeaders->OptionalHeader.ImageBase) {
        PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)((BYTE*)imageBase + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
        DWORD delta = (DWORD)((uintptr_t)imageBase - ntHeaders->OptionalHeader.ImageBase);

        while (reloc->VirtualAddress) {
            WORD* entries = (WORD*)((BYTE*)reloc + sizeof(IMAGE_BASE_RELOCATION));
            for (int i = 0; i < (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2; i++) {
                if (entries[i] & 0x8000) {
                    DWORD* patch = (DWORD*)((BYTE*)imageBase + reloc->VirtualAddress + (entries[i] & 0x0FFF));
                    *patch += delta;
                }
            }
            reloc = (PIMAGE_BASE_RELOCATION)((BYTE*)reloc + reloc->SizeOfBlock);
        }
    }

    PIMAGE_IMPORT_DESCRIPTOR import = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)imageBase + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    while (import->Name) {
        char* dllName = (char*)((BYTE*)imageBase + import->Name);
        HMODULE hModule = GetModuleHandleA(dllName);
        if (!hModule) hModule = LoadLibraryA(dllName);
        if (hModule) {
            PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((BYTE*)imageBase + import->FirstThunk);
            PIMAGE_THUNK_DATA originalThunk = (PIMAGE_THUNK_DATA)((BYTE*)imageBase + import->OriginalFirstThunk);
            if (!originalThunk) originalThunk = thunk;

            while (originalThunk->u1.AddressOfData) {
                if (originalThunk->u1.Ordinal & 0x80000000) {
                    DWORD ordinal = originalThunk->u1.Ordinal & 0xFFFF;
                    thunk->u1.Function = (uintptr_t)GetProcAddress(hModule, (LPCSTR)ordinal);
                }
                else {
                    PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)imageBase + originalThunk->u1.AddressOfData);
                    thunk->u1.Function = (uintptr_t)GetProcAddress(hModule, importByName->Name);
                }
                thunk++;
                originalThunk++;
            }
        }
import++;
    }

    delete[] fileData;
    return imageBase;
}

bool InjectDLL(const std::string& dllPath) {
    std::wstring procName = L"RobloxPlayerBeta.exe";
    g_pid = GetPid(procName);
    if (!g_pid) {
        LogToUI("Roblox not running.");
        return false;
    }

    g_hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, g_pid);
    if (!g_hProcess) {
        LogToUI("Failed to open process.");
        return false;
    }

    LogToUI("Manual mapping DLL...");
    g_mappedDLL = ManualMapDLL(dllPath);
    if (!g_mappedDLL) {
        LogToUI("Manual mapping failed.");
        return false;
    }
    LogToUI("DLL mapped at 0x" + std::to_string((uintptr_t)g_mappedDLL));

    // Get DllMain RVA
    HMODULE hLocalDLL = LoadLibraryA(dllPath.c_str());
    if (!hLocalDLL) {
        LogToUI("Failed to load local DLL.");
        return false;
    }
    FARPROC pDllMain = GetProcAddress(hLocalDLL, "DllMain");
    FreeLibrary(hLocalDLL);

    uintptr_t rvaDllMain = (uintptr_t)pDllMain - (uintptr_t)GetModuleHandleA(NULL);
    uintptr_t remoteDllMain = (uintptr_t)g_mappedDLL + rvaDllMain;

    // Get syscall index from ntdll
    DWORD syscallIndex = GetSyscallIndex();
    if (!syscallIndex) {
        LogToUI("Failed to get syscall index.");
        return false;
    }
    LogToUI("Syscall index: 0x" + std::to_string(syscallIndex));

    // Create syscall stub
    pNtCreateThreadEx NtCreateThreadEx = CreateSyscallStub(syscallIndex);
    if (!NtCreateThreadEx) {
        LogToUI("Failed to create syscall stub.");
        return false;
    }

    // Call DllMain via syscall
    HANDLE hThread = NULL;
    NTSTATUS status = NtCreateThreadEx(&hThread, 0x1FFFFF, NULL, g_hProcess,
        (LPTHREAD_START_ROUTINE)remoteDllMain, g_mappedDLL, 0, 0, 0, 0, NULL);

    if (status < 0 || !hThread) {
        LogToUI("NtCreateThreadEx syscall failed. Status: 0x" + std::to_string(status));
        VirtualFreeEx(g_hProcess, g_mappedDLL, 0, MEM_RELEASE);
        return false;
    }

    WaitForSingleObject(hThread, 5000);
    CloseHandle(hThread);
    LogToUI("DllMain called successfully.");
    return true;
}

LRESULT CALLBACK WindowProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
        g_hEditScript = CreateWindowA("EDIT",
            "print('Hello from C++ Executor!')\n-- Write your script here",
            WS_CHILD | WS_VISIBLE | WS_BORDER | ES_MULTILINE | ES_AUTOVSCROLL | ES_WANTRETURN,
            10, 10, 500, 200, hWnd, NULL, NULL, NULL);

        g_hEditLog = CreateWindowA("EDIT",
            "Ready.\r\n",
            WS_CHILD | WS_VISIBLE | WS_BORDER | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY,
            10, 220, 500, 150, hWnd, NULL, NULL, NULL);

        g_hBtnInject = CreateWindowA("BUTTON", "Inject",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            520, 10, 100, 30, hWnd, (HMENU)1, NULL, NULL);

        g_hBtnExecute = CreateWindowA("BUTTON", "Execute",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            520, 50, 100, 30, hWnd, (HMENU)2, NULL, NULL);

        g_hStatus = CreateWindowA("STATIC", "Status: Ready",
            WS_CHILD | WS_VISIBLE,
            520, 90, 200, 20, hWnd, NULL, NULL, NULL);

        break;
    }
    case WM_COMMAND: {
        if (LOWORD(wParam) == 1) {
            LogToUI("Injecting...");
            char exePath[MAX_PATH];
            GetModuleFileNameA(NULL, exePath, MAX_PATH);
            std::string dllPath = std::string(exePath);
            size_t pos = dllPath.find_last_of("\\/");
            if (pos != std::string::npos) {
                dllPath = dllPath.substr(0, pos + 1) + "payload.dll";
            }

            if (InjectDLL(dllPath)) {
                LogToUI("Injection successful.");
                SetWindowTextA(g_hStatus, "Status: Injected");
            }
            else {
                LogToUI("Injection failed.");
                SetWindowTextA(g_hStatus, "Status: Injection Failed");
            }
        }
        else if (LOWORD(wParam) == 2) {
            LogToUI("Executing script...");
            // You can call remote functions here via CreateRemoteThread if needed
        }
        break;
    }
    case WM_DESTROY: {
        PostQuitMessage(0);
        break;
    }
    default:
        return DefWindowProc(hWnd, msg, wParam, lParam);
    }
    return 0;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int nCmdShow) {
    const char CLASS_NAME[] = "ExecutorWindow";

    WNDCLASSA wc = {};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);

    RegisterClassA(&wc);

    HWND hWnd = CreateWindowExA(
        0,
        CLASS_NAME,
        "NIGGER NIGGA FUCK BITCH",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT,
        650, 450,
        NULL, NULL, hInstance, NULL
    );

    if (!hWnd) return 0;

    ShowWindow(hWnd, nCmdShow);
    UpdateWindow(hWnd);

    MSG msg = {};
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return 0;
}