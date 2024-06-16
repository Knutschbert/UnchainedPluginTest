#pragma once
#include <deque>
#include <string>
#include "sigs.h" //TODO: this may cause issues; included only for F_MaxFuncType on BuildType

struct BuildType {

	void SetName(const char* newName) {
		nameStr = std::string(newName);
	}

	void SetName(const wchar_t* newName) {
		std::wstring ws(newName);
		nameStr = std::string(ws.begin(), ws.end());
	}

	~BuildType() {
		delete[] name;
	}

	uint32_t fileHash = 0;
	uint32_t buildId = 0;
	uint32_t offsets[F_MaxFuncType] = {};
	std::string nameStr = "";
private:
	char* name = nullptr;
};

uint32_t calculateCRC32(const std::string& filename);

// TODO: put these globals where they belong (in the below functions)
// some hooks rely on accessing them directly. This needs to be cleaned up
// btw, they are defined in this class's corresponding cpp file
extern std::deque<BuildType*> configBuilds;
//BuildInfo* curBuildInfo = nullptr;
extern BuildType curBuild;
extern bool jsonDone;
extern bool offsetsLoaded;
extern bool needsSerialization;

void serializeBuilds();

int LoadBuildConfig();