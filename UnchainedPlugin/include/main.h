﻿#pragma once
#include <Sig/Sig.hpp>
#include "sigs.h"

const char* logo = R"( 
_________  .__     .__                .__                    ________             
\_   ___ \ |  |__  |__|___  _______   |  |  _______  ___.__. \_____  \        
/    \  \/ |  |  \ |  |\  \/ /\__  \  |  |  \_  __ \<   |  |  /  ____/   
\     \____|   Y  \|  | \   /  / __ \_|  |__ |  | \/ \___  | /       \    
 \______  /|___|  /|__|  \_/  (____  /|____/ |__|    / ____| \_______ \       
        \/      \/                 \/                \/              \/      
 ____ ___                 .__             .__                     .___            
|    |   \  ____    ____  |  |__  _____   |__|  ____    ____    __| _/           
|    |   / /    \ _/ ___\ |  |  \ \__  \  |  | /    \ _/ __ \  / __ |      
|    |  / |   |  \\  \___ |   Y  \ / __ \_|  ||   |  \\  ___/ / /_/ |      
|______/  |___|  / \___  >|___|  /(____  /|__||___|  / \___  >\____ |          
               \/      \/      \/      \/          \/      \/      \/      
)";

// Helper functions

void log(const char* str) {
	if (GetConsoleWindow()) {
		std::cout << str << std::endl;
	}
}

std::string wstrtos(std::wstring in) {
	//https://stackoverflow.com/a/12097772
	//don't care about encoding/character truncation
	std::string str;
	std::transform(in.begin(), in.end(), std::back_inserter(str), [](wchar_t c) {
		return (char)c;
		});

	return str;
}

std::wstring stowstr(std::string in) {
	//https://stackoverflow.com/a/12097772
	//don't care about encoding/character truncation
	std::wstring str;
	std::transform(in.begin(), in.end(), std::back_inserter(str), [](char c) {
		return (wchar_t)c;
		});

	return str;
}

//TODO: fix this signature
int logWideString(wchar_t* loggedString) {
	if (!GetConsoleWindow()) {
		return 0;
	}	
	
	std::cout << wstrtos(loggedString) << std::endl;
	return 0;
}


long long FindSignature(HMODULE baseAddr, DWORD size, const char* title, const char* signature)
{
	const void* found = nullptr;
	found = Sig::find(baseAddr, size, signature);
	long long diff = 0;
	if (found != nullptr)
	{
		diff = (long long)found - (long long)baseAddr;
#ifdef _DEBUG
		//std::cout << title << ": 0x" << std::hex << diff << std::endl;
		printf("?? -> %s : 0x%llx\n", title, diff);
#endif
	}
#ifdef _DEBUG
	else
		printf("!! -> %s : nullptr\n", title);
		//std::cout << title << ": nullptr" << std::endl;
#endif

		return diff;

}


inline static void Ptch_Nop(unsigned char* address, int size)
{
	unsigned long protect[2];
	VirtualProtect((void*)address, size, PAGE_EXECUTE_READWRITE, &protect[0]);
	memset((void*)address, 0x90, size);
	VirtualProtect((void*)address, size, protect[0], &protect[1]);
}

inline static void Ptch_Repl(unsigned char* address, DWORD newVal)
{
	DWORD d;
	VirtualProtect((void*)address, 1, PAGE_EXECUTE_READWRITE, &d);
	*address = 0xEB; // Patch to JMP
	VirtualProtect((void*)address, 1, d, NULL);
}

// Hook macros

HMODULE baseAddr;
MODULEINFO moduleInfo;

#define DECL_HOOK(retType, funcType, args)    \
	typedef retType (*funcType##_t) args;		\
	funcType##_t o_##funcType;					\
	retType hk_##funcType args

#define HOOK_ATTACH(moduleBase, funcType) \
	MH_CreateHook(moduleBase + curBuild.offsets[F_##funcType], hk_##funcType, reinterpret_cast<void**>(&o_##funcType)); \
	MH_EnableHook(moduleBase + curBuild.offsets[F_##funcType]); 

#define HOOK_FIND_SIG(funcType) \
	if (curBuild.offsets[F_##funcType] == 0)\
		curBuild.offsets[F_##funcType] = FindSignature(baseAddr, moduleInfo.SizeOfImage, #funcType, signatures[F_##funcType]); \
	else printf("-> %s : (conf)\n", #funcType);
	//long long sig_##funcType = FindSignature(baseAddr, moduleInfo.SizeOfImage, #funcType, signatures[F_##funcType]);
