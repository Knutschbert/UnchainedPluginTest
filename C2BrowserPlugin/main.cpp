#include <Windows.h>
#include <MinHook/include/MinHook.h>
#include <iostream>

//#define TARGET_API_ROOT L"localhost"
#define TARGET_API_ROOT L"servers.polehammer.net"

struct FString {
	FString(const wchar_t* str) {
		this->letter_count = lstrlenW(str) + 1;
		this->max_letters = this->letter_count;
		this->str = const_cast<wchar_t*>(str);
	}

	wchar_t* str;
	int letter_count;
	int max_letters;
};

struct GCGObj {
	FString url_base;
};

void log(const char* str) {
#ifndef _DEBUG
	return;
#endif
	std::cout << str << std::endl;

}

int logWideString(wchar_t* str) {
#ifndef _DEBUG
	return 0;
#endif
	int i = 0;
	while (*(char*)str != 0) {
		std::cout << *(char*)str;
		str+=2;
		i++;
	}
	std::cout << std::endl;
	return i;
}

typedef void* (*GetCurrentGames_t)(GCGObj*, void*, void*, void*);
GetCurrentGames_t o_GetCurrentGames;

typedef wchar_t** (*GetMotd_t)(GCGObj* this_ptr, void* a2, void* a3, void* a4);
GetMotd_t o_GetMotd;

void* hk_GetMotd(GCGObj* this_ptr, void* a2, void* a3, void* a4) {
	auto old_base = this_ptr->url_base;
	this_ptr->url_base = FString(L"http://" TARGET_API_ROOT L"/api/tbio");
	void* res = o_GetMotd(this_ptr, a2, a3, a4);

	this_ptr->url_base = old_base;
	log("GetMotd returned");
	return res;
}

void* hk_GetCurrentGames(GCGObj* this_ptr, void* a2, void* a3, void* a4) {
	log("GetCurrentGames called");
	auto old_base = this_ptr->url_base;

	this_ptr->url_base = FString( L"http://" TARGET_API_ROOT "/api/tbio" );
	void* res{ o_GetCurrentGames(this_ptr, a2, a3, a4) };

	this_ptr->url_base = old_base;
	log("GetCurrentGames returned");
	return res;
}

typedef wchar_t** (*SendRequest_t)(GCGObj* this_ptr, FString* a2, FString* a3, FString* a4, FString* a5);
SendRequest_t o_SendRequest;


void* hk_SendRequest(GCGObj* this_ptr, FString* a2, FString* a3, FString* a4, FString* a5) {

	if (a2->letter_count > 0 &&
		wcscmp(L"https://EBF8D.playfabapi.com/Client/Matchmake?sdk=Chiv2_Version", a2->str) == 0)
	{
		FString original = *a2; //save original string and buffer information
		*a2 = FString(L"http://" TARGET_API_ROOT "/api/playfab/Client/Matchmake"); //overwrite with new string
		log("hk_SendRequest Client/Matchmake");
		auto res = o_SendRequest(this_ptr, a2, a3, a4, a5); //run the request as normal with new string
		*a2 = original; //set everything back to normal and pretend nothing happened
		return res;
	}
	return o_SendRequest(this_ptr, a2, a3, a4, a5);
}

unsigned long main_thread(void* lpParameter) {
	log("BrowserPlugin started!");
	MH_Initialize();

	unsigned char* module_base{ reinterpret_cast<unsigned char*>(GetModuleHandleA("Chivalry2-Win64-Shipping.exe")) };

	MH_CreateHook(module_base + 0x13da7d0, hk_GetMotd, reinterpret_cast<void**>(&o_GetMotd));
	MH_EnableHook(module_base + 0x13da7d0);

	MH_CreateHook(module_base + 0x13DA280, hk_GetCurrentGames, reinterpret_cast<void**>(&o_GetCurrentGames));
	MH_EnableHook(module_base + 0x13DA280);

	MH_CreateHook(module_base + 0x14a1250, hk_SendRequest, reinterpret_cast<void**>(&o_SendRequest));
	MH_EnableHook(module_base + 0x14a1250);

	ExitThread(0);
	return 0;
}

int __stdcall DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
	#ifdef _DEBUG
	if (!GetConsoleWindow()) {
		AllocConsole();
		FILE* file_pointer{};
		freopen_s(&file_pointer, "CONOUT$", "w", stdout);
	}
	#endif
	switch (ul_reason_for_call) {
	case DLL_PROCESS_ATTACH: {
		HANDLE thread_handle{ CreateThread(NULL, 0, main_thread, hModule, 0, NULL) };
		if (thread_handle) CloseHandle(thread_handle);
		break;
	}
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return 1;
}