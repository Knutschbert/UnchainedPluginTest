#include "builds.h"
#include <stdint.h>
#include <iostream>
#include <fstream>

#include "tiny-json.h"

#include <nmmintrin.h> // SSE4.2 intrinsics
uint32_t calculateCRC32(const std::string& filename) {
	std::ifstream file(filename, std::ios::binary);
	if (!file.is_open()) {
		std::cerr << "Error opening file: " << filename << std::endl;
		return 0;
	}

	uint32_t crc = 0; // Initial value for CRC-32

	char buffer[4096];
	while (file) {
		file.read(buffer, sizeof(buffer));
		std::streamsize bytesRead = file.gcount();

		for (std::streamsize i = 0; i < bytesRead; ++i) {
			crc = _mm_crc32_u8(crc, buffer[i]);
		}
	}

	file.close();
	return crc ^ 0xFFFFFFFF; // Final XOR value for CRC-32
}

std::deque<BuildType*> configBuilds;
//BuildInfo* curBuildInfo = nullptr;
BuildType curBuild;
bool jsonDone = false;
bool offsetsLoaded = false;
bool needsSerialization = true;

void serializeBuilds()
{
	char buff[2048];
	char* dest = buff;
	if (curBuild.buildId > 0)
	{

		char* pValue;
		size_t len;
		char ladBuff[512];
		errno_t err = _dupenv_s(&pValue, &len, "LOCALAPPDATA");
		if (err != 0) {
			return;
		}
		//TODO: Ensure pValue is not null, or make a note here explaining why it couldn't possibly be null
		strncpy_s(ladBuff, 512 * sizeof(char), pValue, len);
		strncpy_s(ladBuff + len - 1, 256 - len, "\\Chivalry 2\\Saved\\Config\\c2uc.builds.json", 42);

		printf("Config written to:\n\t%s\n", ladBuff);
		std::ofstream out(ladBuff);

		out << "\n{\n\"" << ((curBuild.nameStr.length() > 0) ? curBuild.nameStr.c_str() : "") << "\": {";
		out << "\n\"Build\" : " << curBuild.buildId;
		out << ",\n\"FileHash\" : " << curBuild.fileHash;
		for (uint8_t i = 0; i < F_MaxFuncType; ++i)
			out << ",\n\"" << strFunc[i] << "\": " << curBuild.offsets[i];

		for (auto build : configBuilds)
		{
			out << "\n},\n\"" << ((build->nameStr.length() > 0) ? build->nameStr.c_str() : "") << "\": {";
			out << "\n\"Build\" : " << build->buildId;
			out << ",\n\"FileHash\" : " << build->fileHash;
			for (uint8_t i = 0; i < F_MaxFuncType; ++i)
				out << ",\n\"" << strFunc[i] << "\": " << build->offsets[i];
		}
		out << "\n}";
		out << "\n}";

	}

}

int LoadBuildConfig()
{
	// load config file
	char* pValue;
	size_t len;
	char ladBuff[256];
	errno_t err = _dupenv_s(&pValue, &len, "LOCALAPPDATA");
	strncpy_s(ladBuff, 256, pValue, len);
	strncpy_s(ladBuff + len - 1, 256 - len, "\\Chivalry 2\\Saved\\Config\\c2uc.builds.json", 42);

	std::ifstream file(ladBuff, std::ios::binary);
	if (!file.is_open()) {
		std::cout << "Error opening build config" << std::endl;
		return 0;
	}
	std::string buffer;
	file.seekg(0, std::ios::end);
	buffer.reserve(file.tellg());
	file.seekg(0, std::ios::beg);

	buffer.assign((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
	file.close();

	// parse json
	json_t mem[128];
	const json_t* json = json_create(const_cast<char*>(buffer.c_str()), mem, 128);

	if (!json) {
		puts("Failed to create json parser");
		return EXIT_FAILURE;
	}
	uint32_t curFileHash = calculateCRC32("Chivalry2-Win64-Shipping.exe");

	json_t const* buildEntry;
	needsSerialization = true;
	buildEntry = json_getChild(json);
	while (buildEntry != 0) {
		if (JSON_OBJ == json_getType(buildEntry)) {

			char const* fileSize = json_getPropertyValue(buildEntry, "FileSize");
			json_t const* build = json_getProperty(buildEntry, "Build");
			char const* buildName = json_getName(buildEntry);
			printf("parsing %s\n", buildName);

			json_t const* fileHash = json_getProperty(buildEntry, "FileHash");
			if (!fileHash || JSON_INTEGER != json_getType(fileHash)) {
				puts("Error, the FileHash property is not found.");
				return EXIT_FAILURE;
			}
			if (!build || JSON_INTEGER != json_getType(build)) {
				puts("Error, the Build property is not found.");
				return EXIT_FAILURE;
			}
			// compare hash
			uint64_t fileHashVal = json_getInteger(fileHash);
			bool hashMatch = fileHashVal == curFileHash;

			// Create Build Config entry
			BuildType bd_;
			BuildType& bd = bd_;

			if (hashMatch)
			{
				bd = curBuild;
				needsSerialization = false;
				printf("Found matching Build: %s\n", buildName);
			}

			printf("%s : %u\n", buildName, strlen(buildName));

			if (strlen(buildName) > 0)
			{
				bd.SetName(buildName);
			}

			bd.buildId = (uint32_t)json_getInteger(build);
			bd.fileHash = (uint32_t)fileHashVal;
			for (uint8_t i = 0; i < F_MaxFuncType; ++i)
			{
				if (const json_t* GetMotd_j = json_getProperty(buildEntry, strFunc[i]))
				{
					if (JSON_INTEGER == json_getType(GetMotd_j))
						if (uint32_t offsetVal = (uint32_t)json_getInteger(GetMotd_j))
							bd.offsets[i] = offsetVal;
					// offsets not found here will be scanned later
				}
				else if (hashMatch) needsSerialization = true;
			}

			if (hashMatch)
				curBuild = bd;
			else
				configBuilds.push_back(new BuildType(bd));
		}
		buildEntry = json_getSibling(buildEntry);
	}

	return 0;
}