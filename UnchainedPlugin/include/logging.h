/*
	Global logging functions. Use these INSTEAD of printf or cout/wcout and their similars for consistency and
	eventual global logging configuration.

	TODO: make this use a proper logging library
*/
#pragma once
#include "UE4.h"
int logFString(FString str);

void log(const char* str);

int logWideString(wchar_t* str);

int logWideString(const wchar_t* str);