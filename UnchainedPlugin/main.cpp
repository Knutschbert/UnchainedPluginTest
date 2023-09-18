#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <psapi.h>
#include <MinHook/include/MinHook.h>
#include <iostream>
#include <deque>
#include <fcntl.h>
#include <io.h>
#include <fstream>
#include <iomanip>
#include <mutex>
#include <queue>
#include <string>
#include <iostream>
#include <sstream>
#include <direct.h>
//always open output window
#define _DEBUG
#include "include/main.h"
#include "tiny-json/tiny-json.h"


//black magic for the linker to get winsock2 to work
#pragma comment(lib, "Ws2_32.lib")

//always open output window
#define _DEBUG

//#define TARGET_API_ROOT L"localhost"
#define TARGET_API_ROOT L"servers.polehammer.net"
#ifdef _DEBUG
	#define PROTOCOL L"http"
#else
	#define PROTOCOL L"https"
#endif

#include <cstdint>
#include <nmmintrin.h> // SSE4.2 intrinsics
#include <regex>

struct BuildType {
	~BuildType() {
		delete[] name;
	}

	void SetName(const char* newName) {
		nameStr = std::string(newName);
	}

	void SetName(const wchar_t* newName) {
		std::wstring ws(newName);
		nameStr = std::string(ws.begin(), ws.end());
	}

	uint32_t fileHash = 0;
	uint32_t buildId = 0;
	uint32_t offsets[F_MaxFuncType] = {};
	std::string nameStr = "";
private:
	char* name = nullptr;
};

std::deque<BuildType*> configBuilds;

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

// Browser plugin
DECL_HOOK(void*, GetMotd, (GCGObj* this_ptr, void* a2, GetMotdRequest* request, void* a4)) {
	log("GetMotd Called");

	auto old_base = this_ptr->url_base;

	auto originalToken = request->token;
	auto emptyToken = FString(L"");

	try {
		this_ptr->url_base = FString( PROTOCOL L"://" TARGET_API_ROOT L"/api/tbio");
		request->token = emptyToken;
		void* res = o_GetMotd(this_ptr, a2, request, a4);
		this_ptr->url_base = old_base;
		request->token = originalToken;
		log("GetMotd returned");
		return res;
	}
	catch (...) {
		this_ptr->url_base = old_base;
		request->token = originalToken;
		throw;
	}
}

DECL_HOOK(void*, GetCurrentGames, (GCGObj* this_ptr, void* a2, GetCurrentGamesRequest* request, void* a4)) {
	log("GetCurrentGames called");

	auto old_base = this_ptr->url_base;

	auto originalToken = request->token;
	auto emptyToken = FString(L"");

	try {
		this_ptr->url_base = FString(PROTOCOL L"://" TARGET_API_ROOT L"/api/tbio");
		request->token = emptyToken;
		void* res = o_GetCurrentGames(this_ptr, a2, request, a4);
		this_ptr->url_base = old_base;
		request->token = originalToken;
		log("GetMotd returned");
		return res;
	}
	catch (...) {
		this_ptr->url_base = old_base;
		request->token = originalToken;
		throw;
	}
}

DECL_HOOK(void*, SendRequest, (GCGObj* this_ptr, FString* fullUrlInputPtr, FString* bodyContentPtr, FString* authKeyHeaderPtr, FString* authKeyValuePtr)) {
	if (fullUrlInputPtr->letter_count > 0 &&
		wcscmp(L"https://EBF8D.playfabapi.com/Client/Matchmake?sdk=Chiv2_Version", fullUrlInputPtr->str) == 0)
	{
		FString original = *fullUrlInputPtr; //save original string and buffer information
		*fullUrlInputPtr = FString(PROTOCOL L"://" TARGET_API_ROOT "/api/playfab/Client/Matchmake"); //overwrite with new string
		log("hk_SendRequest Client/Matchmake");

		auto empty = FString(L""); // Send empty string for auth, so that our backend isn't getting user tokens.
		try {
			auto res = o_SendRequest(this_ptr, fullUrlInputPtr, bodyContentPtr, authKeyHeaderPtr, &empty); //run the request as normal with new string
			*fullUrlInputPtr = original; //set everything back to normal and pretend nothing happened
			return res;
		}
		catch (...) {
			*fullUrlInputPtr = original; //set everything back to normal and pretend nothing happened
			throw;
		}
		;
	}
	return o_SendRequest(this_ptr, fullUrlInputPtr, bodyContentPtr, authKeyHeaderPtr, authKeyValuePtr);
}
// end browser plugin

// AssetLoaderPlugin

DECL_HOOK(long long, FindFileInPakFiles_1, (void* this_ptr, const wchar_t* Filename, void** OutPakFile, void* OutEntry)) {
	auto attr{ GetFileAttributesW(Filename) };
	if (attr != INVALID_FILE_ATTRIBUTES && Filename && wcsstr(Filename, L"../../../")) {
		if (OutPakFile) OutPakFile = nullptr;
		return 0;
	}

	return o_FindFileInPakFiles_1(this_ptr, Filename, OutPakFile, OutEntry);
}

DECL_HOOK(long long, FindFileInPakFiles_2, (void* this_ptr, const wchar_t* Filename, void** OutPakFile, void* OutEntry)) {
	auto attr{ GetFileAttributesW(Filename) };
	if (attr != INVALID_FILE_ATTRIBUTES && Filename && wcsstr(Filename, L"../../../")) {
		if (OutPakFile) OutPakFile = nullptr;
		return 0;
	}

	return o_FindFileInPakFiles_2(this_ptr, Filename, OutPakFile, OutEntry);
}

DECL_HOOK(long long, IsNonPakFilenameAllowed, (void* this_ptr, void* InFilename)) {
	return 1;
}

//FString* __cdecl
//UUserFeedbackAndBugReportsLibrary::GetGameInfo(FString* __return_storage_ptr__, UWorld* param_1)
DECL_HOOK(FString*, GetGameInfo, (FString* ret_ptr, void* uWorld))
{
	auto val = o_GetGameInfo(ret_ptr, uWorld);
#ifdef _DEBUG
	std::wcout << "GetGameInfo: " << *val->str << std::endl;
#endif
	return val;
}

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

DECL_HOOK(FString*, FViewport, (FViewport_C* this_ptr, void* viewportClient))
{
	auto val = o_FViewport(this_ptr, viewportClient);
	wchar_t* buildNr = wcschr(this_ptr->AppVersionString.str, L'+') + 1;
	if (buildNr != nullptr)
	{
		uint32_t buildId = _wtoi(buildNr);
		if (curBuild.buildId == 0 || curBuild.nameStr.length() == 0)
		{
			needsSerialization = true;
			curBuild.SetName(this_ptr->AppVersionString.str + 7);

			curBuild.buildId = buildId;
			curBuild.fileHash = calculateCRC32("Chivalry2-Win64-Shipping.exe");
		}
		if (curBuild.nameStr.length() > 0)
		{
			printf("Build String found!%s\n\t%s\n", (curBuild.buildId == 0) ? "" : " (loaded)", curBuild.nameStr.c_str());

			if (offsetsLoaded && needsSerialization)
				serializeBuilds();
		}

#ifdef _DEBUG
		//std::wcout << this_ptr->AppVersionString.str << ": " << buildNr << " " << buildId << std::endl;
#endif
	}
	return val;
}

std::mutex queueLock;
std::queue<std::unique_ptr<std::wstring>> commandQueue;
static void* cached_this;
static FString const* cached_str;
DECL_HOOK(FString, ConsoleCommand, (void* this_ptr, FString const& str, bool b)) {
	if (this_ptr == NULL) {
		this_ptr = cached_this;
	}
	else {
		cached_this = this_ptr;
		cached_str = &str;
	}
#ifdef _DEBUG_
	log("[RCON][DEBUG]: PlayerController Exec called with:");
	logWideString(str.str);
#endif
	const wchar_t* interceptPrefix = L"RCON_INTERCEPT";
	//if the command starts with the intercept prefix
	//TODO: clean up mutex stuff here. Way too sloppy to be final
	if (wcslen(str.str) >= 14 && memcmp(str.str, interceptPrefix, lstrlenW(interceptPrefix) * sizeof(wchar_t)) == 0) {
#ifdef _DEBUG_
		log("[RCON][DEBUG]: Intercept command detected");
#endif
		queueLock.lock();
		if (commandQueue.size() > 0) { //if the queue is empty we want to just return as normal
			//check if the intercept command is large enough to contain the substitute command
			if (wcslen(commandQueue.front()->c_str()) > wcslen(str.str)) {
				log("[WARNING][RCON]: Intercept command too small to contain substitute command. Command was thrown out.");
				//throw away the substitute command to keep it from
				//clogging the queue. In a headless instance, it's unlikely
				//the intercepted command will ever be larger than it is now.
				commandQueue.pop();
				queueLock.unlock();
				return o_ConsoleCommand(this_ptr, str, b);
			}
			//pull the substitute command off the queue
			auto command = std::move(commandQueue.front());
			commandQueue.pop();
			queueLock.unlock(); //unlock the mutex
			//log("pretend we ran the command");
			//copy the substitute command over top of the intercepted command
			wcscpy_s(str.str, lstrlenW(str.str) + 1, command->c_str());

			log("[RCON]: command substituted:");
			logWideString(str.str);
			return o_ConsoleCommand(this_ptr, str, b);
		}
		queueLock.unlock();
	}
	//std::cout << "0x" << std::hex << this_ptr << std::endl;
	return o_ConsoleCommand(this_ptr, str, b);
}

//parse the command line for the rcon flag, and return the port specified
//if not port was specified, or the string that was supposed to be a port number 
//was invalid, then -1 is returned
int parsePortParams(std::wstring commandLine, size_t flagLoc) {
	size_t portStart = commandLine.find(L" ", flagLoc); //next space
	if (portStart == std::wstring::npos) {
		return -1;
	}
	size_t portEnd = commandLine.find(L" ", portStart + 1); //space after that

	std::wstring port = portEnd != std::wstring::npos
		? commandLine.substr(portStart, portEnd - portStart)
		: commandLine.substr(portStart);

	//log("found port:");
	//logWideString(const_cast<wchar_t*>(port.c_str()));
	try {
		return std::stoi(port);
	}
	catch (std::exception e) {
		return -1;
	}
}

// Returns position of a substring in command line args or -1
size_t CmdGetParam(const wchar_t* param)
{
	size_t res = std::wstring(GetCommandLineW()).find(param);
	bool found = (res != std::wstring::npos);
	
	//wprintf(L"CmdGetParam: %ls %ls %d\n", param, (found ? L":) found" : L":( not found"), found ? res : -1);
	return found ? res : -1;
}

// Returns parsed parameter (1 char spacing req), pre-/appends text if needed.
std::wstring CmdParseParam(const wchar_t* param, const wchar_t * addPrefix = L"", const wchar_t * addSuffix = L"")
{
	std::wstring commandLine = GetCommandLineW();
	size_t paramPos = CmdGetParam(param);
	if (paramPos == -1)
		return L"";

	size_t offset = paramPos + lstrlenW(param) + 1;
	size_t paramEnd = commandLine.find(L" ", offset);
	if (paramPos == -1)
		return L"";
	std::wstring res = commandLine.substr(offset, paramEnd - offset);

	/*logWideString(const_cast<wchar_t*>(param));
	logWideString(const_cast<wchar_t*>(res.c_str()));*/
	return (addPrefix + res + addSuffix).c_str();
}

//#define FRONTEND_MAP_FMT L"Frontend%ls?mods=%ls?nextmap=%ls?nextmods=%ls?defmods=%ls"
DECL_HOOK(bool, LoadFrontEndMap, (void* this_ptr, FString* param_1))
{
	static wchar_t szBuffer[512];


	static bool init = false;
	if (!init) {
		auto modStr = CmdParseParam(L"--all-mod-actors", L"?mods=");
		auto defModStr = CmdParseParam(L"--default-mod-actors", L"?defmods=");
		auto nextMapStr = CmdParseParam(L"--next-map-name", L"?nextmap=");
		auto nextModsStr = CmdParseParam(L"--next-map-mod-actors", L"?nextmods=");

		/*
		if (!modStr.empty())
			wprintf(L"?mods=%ls", modStr.c_str());
		if (!nextMapStr.empty())
			wprintf(L"?nextmap=%ls", nextMapStr.c_str());
		if (!nextModsStr.empty())
			wprintf(L"?nextmods=%ls", nextModsStr.c_str());
		if (!defModStr.empty())
			wprintf(L"?defmods=%ls\n", defModStr.c_str());
		*/

		log("Frontend Map params: ");
		wsprintfW(szBuffer, L"Frontend%ls%ls%ls%ls%ls", (CmdGetParam(L"-rcon") == -1) ? L"" : L"?rcon", modStr.c_str(), nextMapStr.c_str(), nextModsStr.c_str(), defModStr.c_str());
		logWideString(szBuffer);
		std::wstring ws(param_1->str);
		std::string nameStr = std::string(ws.begin(), ws.end());
		//printf("LoadFrontEndMap: %s %d\n", nameStr.c_str(), param_1->max_letters);
		init = true;
		return o_LoadFrontEndMap(this_ptr, new FString(szBuffer));
	}
	else
		return o_LoadFrontEndMap(this_ptr, param_1);
}

bool extractPlayerCommand(const wchar_t* input, std::wstring& playerName, std::wstring& command) {
	// Define the regular expression pattern
	std::wregex pattern(L"(.+) <0>: /cmd (.+)");

	// Convert the input to a wstring
	std::wstring inputString(input);

	// Define a wsmatch object to store the matched groups
	std::wsmatch matches;

	// Try to match the pattern in the input string
	if (std::regex_search(inputString, matches, pattern)) {
		if (matches.size() == 3) {
			playerName = matches[1].str();
			command = matches[2].str();
			return true; // Match found
		}
	}

	return false; // No match found
}

#define LOG_PATH ""

bool IsServerStart()
{
	bool isHeadless = CmdGetParam(L"-nullrhi") != -1;
	bool isSetToTravel = CmdGetParam(L"--next-map-name") != -1;
	return isHeadless || isSetToTravel;
}


DECL_HOOK(void, ExecuteConsoleCommand, (FString2* param)) {
	log("EXECUTECONSOLECMD:");
	logWideString(param->str);
	o_ExecuteConsoleCommand(param);
}

void* CurGameMode = NULL;
// ATBLGameMode * __cdecl UTBLSystemLibrary::GetTBLGameMode(UObject *param_1)
DECL_HOOK(void*, GetTBLGameMode, (void* uobj)) {
	//log("GetTBLGameMode");
	CurGameMode = o_GetTBLGameMode(uobj);
	return CurGameMode;
}

//FText* __cdecl FText::AsCultureInvariant(FText* __return_storage_ptr__, FString* param_1)
DECL_HOOK(void*, FText_AsCultureInvariant, (void* ret_ptr, FString2* input)) {

	if (input->str != NULL) {
		printf("FText_AsCultureInvariant: ");
		logWideString(input->str);
	}
	return o_FText_AsCultureInvariant(ret_ptr, input);
}

//void __thiscall ATBLGameMode::BroadcastLocalizedChat(ATBLGameMode *this,FText *param_1,Type param_2)
DECL_HOOK(void, BroadcastLocalizedChat, (void* game_mode, FText* text, uint8_t chat_type)) {
	log("BroadcastLocalizedChat");
	return o_BroadcastLocalizedChat(game_mode, text, chat_type);
}

/*
void __thiscall
APlayerController::ClientMessage
		  (APlayerController *this,FString *param_1,FName param_2,float param_3)
*/
DECL_HOOK(void, ClientMessage, (void* this_ptr, FString* param_1, void * param_2, float param_3))
{
	std::wstring commandLine = GetCommandLineW();
	size_t flagLoc = commandLine.find(L"--next-map");
	bool egs = CmdGetParam(L"-epicapp=Peppermint") != -1;
	static uint64_t init = false;
	//log("ClientMessage");

	char* pValue;
	size_t len;
	char ladBuff[256];
	errno_t err = _dupenv_s(&pValue, &len, "LOCALAPPDATA");

	// TODO: make this nicer
	strncpy_s(ladBuff, 256, pValue, len);
	strncpy_s(ladBuff + len - 1, 256 - len, "\\Chivalry 2\\Saved\\Logs\\Unchained", 34);

	_mkdir(ladBuff);
	sprintf_s(ladBuff, 256, "%s\\Chivalry 2\\Saved\\Logs\\Unchained\\ClientMessage%s%s.log",
		pValue, (IsServerStart() ? "-server" : "-client"), (egs ? "-egs" : "-steam"));
	if (!init)
		log(ladBuff);
	//log(ladBuff);
	std::wofstream  out(ladBuff, init++ ? std::ios_base::app : std::ios_base::trunc);
	if (out.is_open())
		out << init << L":: " << param_1->str << std::endl;
	else
		log("Can't open ClientMessage log for writing.");

	/*if (flagLoc == std::wstring::npos) {
		o_ClientMessage(this_ptr, param_1, param_2, param_3);
		return;
	}*/

	static std::wstring playerName;
	auto command = std::make_unique<std::wstring>();

	if (extractPlayerCommand(param_1->str, playerName, *command)) {
		std::wcout << L"Player Name: " << playerName << std::endl;
		std::wcout << L"Command: " << command->c_str() << std::endl;

		FText txt;
		void * res = o_FText_AsCultureInvariant(&txt, new FString2(L"Hello from UnchainedPlugin"));
		if (res != NULL && CurGameMode != NULL)
		{
			log("We Gucci");
			o_BroadcastLocalizedChat(CurGameMode, (FText *)res, 3);
		}

		queueLock.lock();
		log("Executing command");
		logWideString(const_cast<wchar_t*>(command->c_str()));
		//commandQueue.emplace(std::move(command)); //put the command into the queue
		queueLock.unlock();
		auto empty = FString2(command->c_str());

		o_ExecuteConsoleCommand(&empty);
		if (false) {
			wcscpy_s(param_1->str, lstrlenW(param_1->str) + 1, command->c_str());
			o_ConsoleCommand(cached_this, *param_1, false);
		}
	}
	else {
		//std::wcout << L"No valid match found." << std::endl;
	}
	o_ClientMessage(this_ptr, param_1, param_2, param_3);
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

void handleRCON() {
	MH_Initialize();

	std::wstring commandLine = GetCommandLineW();
	size_t flagLoc = commandLine.find(L"-rcon");
	if (flagLoc == std::wstring::npos) {
		ExitThread(0);
		return;
	}

	log("[RCON]: Found -rcon flag. RCON will be enabled.");

	int port = parsePortParams(commandLine, flagLoc);
	if (port == -1) {
		port = 9001; //default port
	}

	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		log("[RCON][FATAL]: Failed to initialize Winsock!");
		ExitThread(0);
		return;
	}

	log((std::string("[RCON][INFO]: Opening RCON server socket on TCP/") + std::to_string(port)).c_str());

	SOCKET listenSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	inet_pton(AF_INET, "0.0.0.0", &addr.sin_addr);

	bind(listenSock, (sockaddr*)&addr, sizeof(addr));
	listen(listenSock, SOMAXCONN);


	while (true) {
		//set up a new command string
		auto command = std::make_unique<std::wstring>();
		log("[RCON]: Waiting for command");
		//get a command from a socket
		int addrLen = sizeof(addr);
		SOCKET remote = accept(listenSock, (sockaddr*)&addr, &addrLen);
		log("[RCON]: Accepted connection");
		if (remote == INVALID_SOCKET) {
			log("[RCON][FATAL]: invalid socket error");
			return;
		}
		const int BUFFER_SIZE = 256;
		//create one-filled buffer
		char buffer[BUFFER_SIZE + 1];
		for (int i = 0; i < BUFFER_SIZE + 1; i++) {
			buffer[i] = 1;
		}
		int count; //holds number of received bytes 
		do {
			count = recv(remote, (char*)&buffer, BUFFER_SIZE, 0); //receive a chunk (may not be the whole command)
			buffer[count] = 0; //null-terminate it implicitly
			//convert to wide string
			std::string chunkString(buffer, count);
			std::wstring wideChunkString(chunkString.begin(), chunkString.end() - 1);
			*command += wideChunkString; //append this chunk to the command
		} while (buffer[count - 1] != '\n');
		//we now have the whole command as a wide string
		closesocket(remote);

		if (command->size() == 0) {
			continue;
		}

		//add into command queue
		queueLock.lock();
		log("[RCON]: added command to queue: ");
		logWideString(const_cast<wchar_t*>(command->c_str()));
		commandQueue.emplace(std::move(command)); //put the command into the queue
		queueLock.unlock();
	}

	return;
}

inline static void Nop(unsigned char* address, int size)
{
	unsigned long protect[2];
	VirtualProtect((void*)address, size, PAGE_EXECUTE_READWRITE, &protect[0]);
	memset((void*)address, 0x90, size);
	VirtualProtect((void*)address, size, protect[0], &protect[1]);
}

unsigned long main_thread(void* lpParameter) {
	log(logo);
	log("Chivalry 2 Unchained Plugin");
	log("\nCommand line args:\n");
	logWideString(GetCommandLineW());
	log("\n");

	MH_Initialize();

	// https://github.com/HoShiMin/Sig
	const void* found = nullptr;
	LoadBuildConfig();
	baseAddr = GetModuleHandleA("Chivalry2-Win64-Shipping.exe");

	int file_descript;
	//unsigned long file_size;
	errno_t err = _sopen_s(&file_descript, "Chivalry2-Win64-Shipping.exe", O_RDONLY, _SH_DENYNO, 0);
	if (err)
		std::cout << "error " << err << std::endl;

	// Get the size of the file
	off_t file_size = _filelength(file_descript);

	//MODULEINFO moduleInfo;	
	GetModuleInformation(GetCurrentProcess(), baseAddr, &moduleInfo, sizeof(moduleInfo));

	unsigned char* module_base{ reinterpret_cast<unsigned char*>(baseAddr) };

	for (uint8_t i = 0; i < F_MaxFuncType; ++i)
	{
		if (curBuild.offsets[i] == 0)
			curBuild.offsets[i] = FindSignature(baseAddr, moduleInfo.SizeOfImage, strFunc[i], signatures[i]);
		else printf("ok -> %s : (conf)\n", strFunc[i]);
		if (i == F_FViewport)
		{
			HOOK_ATTACH(module_base, FViewport);
		}
	}

	char buff[512];
	char* dest = buff;

	log("Serializing builds");
	offsetsLoaded = true;
	serializeBuilds();
	// official
	//auto sig_SendRequest= 0x14a1250;
	//auto sig_GetMotd = 0x13da7d0;
	//auto sig_GetCurrentGames = 0x13da280;
	//auto sig_IsNonPakFilenameAllowed = 0x2fc3ce0;
	//auto sig_FindFileInPakFiles_1 = 0x2fbf1a0;
	//auto sig_FindFileInPakFiles_2 = 0x2fbf280;
	//auto sig_UTBLLocalPlayer = 0x199cda3;

	// ptr
	//auto sig_SendRequest = 0x1425a10;
	//auto sig_GetMotd = 0x135eb70;
	//auto sig_GetCurrentGames = 0x135e620;
	//auto sig_IsNonPakFilenameAllowed = 0x2f4dd80;
	//auto sig_FindFileInPakFiles_1 = 0x2f49240;
	//auto sig_FindFileInPakFiles_2 = 0x2f49320;
	//auto sig_UTBLLocalPlayer = 0x1924926;

	//HOOK_ATTACH(module_base, FViewport);
	HOOK_ATTACH(module_base, GetMotd);
	HOOK_ATTACH(module_base, GetCurrentGames);
	HOOK_ATTACH(module_base, SendRequest);
	HOOK_ATTACH(module_base, IsNonPakFilenameAllowed);
	HOOK_ATTACH(module_base, FindFileInPakFiles_1);
	HOOK_ATTACH(module_base, FindFileInPakFiles_2);
	HOOK_ATTACH(module_base, GetGameInfo);
	HOOK_ATTACH(module_base, ConsoleCommand);
	HOOK_ATTACH(module_base, LoadFrontEndMap);
	HOOK_ATTACH(module_base, ClientMessage);
	HOOK_ATTACH(module_base, ExecuteConsoleCommand);
	HOOK_ATTACH(module_base, GetTBLGameMode);
	HOOK_ATTACH(module_base, FText_AsCultureInvariant);
	HOOK_ATTACH(module_base, BroadcastLocalizedChat);
	
	// ServerPlugin
	auto cmd_permission{ module_base + curBuild.offsets[F_UTBLLocalPlayer_Exec] }; // Patch for command permission when executing commands (UTBLLocalPlayer::Exec)

	// 75 1A 45 84 ED 75 15 48 85 F6 74 10 40 38 BE ? ? ? ? 74 07 32 DB E9 ? ? ? ? 48 8B 5D 60 49 8B D6 4C 8B 45 58 4C 8B CB 49 8B CF (Points directly to instruction: first JNZ)

	DWORD d;
	VirtualProtect(cmd_permission, 1, PAGE_EXECUTE_READWRITE, &d);
	*cmd_permission = 0xEB; // Patch to JMP
	VirtualProtect(cmd_permission, 1, d, NULL); //TODO: Convert patch to hook.
	ExitThread(0);
	

	log("Functions hooked. Continuing to RCON");
	handleRCON(); //this has an infinite loop for commands! Keep this at the end!

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