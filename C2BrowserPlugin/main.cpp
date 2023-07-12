#include <Windows.h>
#include <MinHook/include/MinHook.h>

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

typedef void* (*GetCurrentGames_t)(GCGObj*, void*, void*, void*);
GetCurrentGames_t o_GetCurrentGames;

typedef FString* (*ConcatUrl_t)(FString*, FString*);
ConcatUrl_t o_ConcatUrl;

void* hk_GetCurrentGames(GCGObj* this_ptr, void* a2, void* a3, void* a4) {
	auto old_base = this_ptr->url_base;

	this_ptr->url_base = FString( L"https://google.com" );
	void* res{ o_GetCurrentGames(this_ptr, a2, a3, a4) };

	this_ptr->url_base = old_base;
	return res;
}

FString* hk_ConcatUrl(FString* final_url, FString* url_path) {
	if (wcscmp(url_path->str, L"/Client/Matchmake") != 0) return o_ConcatUrl(final_url, url_path);
	
	const wchar_t* custom_url{ L"https://google.com/Client/Matchmake" };
	final_url->letter_count = lstrlenW(custom_url) + 1;

	wcscpy_s(final_url->str, static_cast<size_t>(final_url->letter_count), custom_url);

	return final_url;
}

unsigned long main_thread(void* lpParameter) {
	MH_Initialize();

	unsigned char* module_base{ reinterpret_cast<unsigned char*>(GetModuleHandleA("Chivalry2-Win64-Shipping.exe")) };

	MH_CreateHook(module_base + 0x13DA280, hk_GetCurrentGames, reinterpret_cast<void**>(&o_GetCurrentGames));
	MH_EnableHook(module_base + 0x13DA280);

	MH_CreateHook(module_base + 0x14ACB70, hk_ConcatUrl, reinterpret_cast<void**>(&o_ConcatUrl));
	MH_EnableHook(module_base + 0x14ACB70);

	ExitThread(0);
	return 0;
}

int __stdcall DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
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