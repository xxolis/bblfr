#include <Windows.h>
#include <lua.hpp>
#include <string>
#include "internal.h"

typedef lua_State* (__fastcall* GetLuaState_t)();
typedef void(__fastcall* TaskDefer_t)(void(*func)(void*), void* arg);
typedef void(__fastcall* TaskSynchronize_t)();

lua_State* g_L = nullptr;
bool g_ready = false;

void WriteLog(const std::string& msg) {
    char dllPath[MAX_PATH];
    GetModuleFileNameA(GetModuleHandleA(NULL), dllPath, MAX_PATH);
    std::string path = dllPath;
    size_t pos = path.find_last_of("\\/");
    if (pos != std::string::npos) path = path.substr(0, pos + 1);
    path += "dll_log.txt";

    HANDLE hFile = CreateFileA(path.c_str(), GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        SetFilePointer(hFile, 0, NULL, FILE_END);
        std::string logMsg = msg + "\r\n";
        DWORD written;
        WriteFile(hFile, logMsg.c_str(), (DWORD)logMsg.size(), &written, NULL);
        CloseHandle(hFile);
    }
}

lua_State* GetLua() {
    HMODULE hRoblox = GetModuleHandleA("RobloxPlayerBeta.exe");
    if (!hRoblox) return nullptr;
    GetLuaState_t getLua = (GetLuaState_t)((uintptr_t)hRoblox + RBX::GetLuaState);
    if (getLua) {
        lua_State* L = getLua();
        if (L) return L;
    }
    uintptr_t luaStatePtr = (uintptr_t)hRoblox + RBX::GetLuaState;
    return *(lua_State**)luaStatePtr;
}

void ExecuteScript(const std::string& script) {
    if (!g_L) return;
    if (luaL_loadstring(g_L, script.c_str()) == LUA_OK) {
        lua_pcall(g_L, 0, 0, 0);
    }
}

extern "C" __declspec(dllexport) void RunScript(const char* script) {
    if (!g_ready || !script) return;
    ExecuteScript(std::string(script));
}

DWORD WINAPI InitThread(LPVOID) {
    Sleep(2000);
    g_L = GetLua();
    if (g_L) {
        lua_pushcfunction(g_L, [](lua_State* L) { lua_pushinteger(L, 5); return 1; });
        lua_setglobal(g_L, "printidentity");
        lua_pushcfunction(g_L, [](lua_State* L) { lua_pushstring(L, "JSExecutor"); return 1; });
        lua_setglobal(g_L, "identifyexecutor");
        luaL_dostring(g_L, "game:GetService('RunService').Heartbeat:Connect(function() end)");
        g_ready = true;
    }
    return 0;
}

BOOL APIENTRY DllMain(HMODULE h, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(h);
        CreateThread(NULL, 0, InitThread, NULL, 0, NULL);
    }
    return TRUE;
}