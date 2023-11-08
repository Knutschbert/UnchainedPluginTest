#pragma once
#include <Windows.h>
#include <cstdint>

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

	FString Concat(FString& other)
	{
		// Concatenate two strings
		wchar_t* new_str = new wchar_t[this->letter_count + other.letter_count - 1];
		lstrcpyW(new_str, this->str);
		lstrcatW(new_str, other.str);
		return FString(new_str);
	}

	FString& Append(const FString& other) {
		// Calculate new length, adding one for the null terminator.
		int new_length = this->letter_count + other.letter_count + 1;
		wchar_t* new_str = new wchar_t[new_length];

		// Copy the original string to the new memory.
		lstrcpyW(new_str, this->str);

		// Concatenate the other string.
		lstrcatW(new_str, other.str);

		// Free the old memory.
		delete[] this->str;

		// Assign the new memory to the str member and update the letter count.
		this->str = new_str;
		this->letter_count = new_length - 1;  // Corrected the length.

		return *this;
	}

	bool Contains(const FString& substr)
	{
		const wchar_t* found = wcsstr(this->str, substr.str);
		return (found != nullptr);
	}

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
