#pragma once
#include <Windows.h>
#include <cstdint>
#include <string>

// UE Types

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

struct TextData {

};

struct FText {

};

struct USkeletalMeshComponent {
	uint8_t ph[0x804];
	bool bOnlyAllowAutonomousTickPose;
};

//FViewport* __thiscall FViewport::FViewport(FViewport* this, FViewportClient* param_1)
struct FViewport_C
{
	uint8_t ph[0x20];
	FString AppVersionString;
};

struct GCGObj {
	FString url_base;
};

struct FUniqueNetIdRepl {};

struct UAbilitySpec {};

struct ECharacterControlEvent {};