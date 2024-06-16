#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <psapi.h>
#include <MinHook/include/MinHook.h>
#include <iostream>
#include <fcntl.h>
#include <io.h>
#include <fstream>
#include <iomanip>
#include <mutex>
#include <string>

#include <direct.h>

//always open output window
#define _DEBUG
#include "constants.h"
#include "main.h"
#include "Chivalry2.h"
#include "UE4.h"
#include "logging.h"
#include "nettools.h"
#include "commandline.h"
#include "builds.h" 

//black magic for the linker to get winsock2 to work
//TODO: properly add this to the linker settings
#pragma comment(lib, "Ws2_32.lib")

#include <cstdint>
#include <regex>

DECL_HOOK(void, FString_AppendChars, (FString* this_ptr, const wchar_t* Str, int Count)) {
	o_FString_AppendChars(this_ptr, Str, Count);
}

// Distributed bans
DECL_HOOK(void, PreLogin, (ATBLGameMode* this_ptr, const FString& Options, const FString& Address, const FUniqueNetIdRepl& UniqueId, FString& ErrorMessage)) {
	std::wstring addressString = Address.str;
	logWideString((addressString + L" is attempting to connect.").c_str());

	o_PreLogin(this_ptr, Options, Address, UniqueId, ErrorMessage);
	
	// An error is already present
	if (ErrorMessage.letter_count != 0)
		return;

	log("Checking Unchained ban status.");

	std::wstring path = L"/api/v1/check-banned/";
	path.append(addressString);
	std::wstring apiUrl = GetApiUrl(path.c_str());
	std::wstring result = HTTPGet(&apiUrl);

	if (result.empty()) {
		log("Failed to get ban status");
		return;
	}

	bool banned = result.find(L"true") != std::wstring::npos;

	if (banned) {
		std::wstring message = L"You are banned from this server.";
		hk_FString_AppendChars(&ErrorMessage, message.c_str(), message.length());
	}


	std::wstring suffix = banned ?
		L" is banned" : L" is not banned";

	logWideString((addressString + suffix).c_str());
}

// Browser plugin
DECL_HOOK(void*, GetMotd, (GCGObj* this_ptr, void* a2, GetMotdRequest* request, void* a4)) {
	log("GetMotd Called");

	auto old_base = this_ptr->url_base;

	auto originalToken = request->token;
	auto emptyToken = FString(L"");

	try {
		this_ptr->url_base = FString(GetApiUrl(L"/api/tbio").c_str());
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
		this_ptr->url_base = FString(GetApiUrl(L"/api/tbio").c_str());
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

DECL_HOOK(FOwnershipResponse*, GetOwnershipFromPlayerControllerAndState, (FOwnershipResponse * result, void* PlayerController, void* PlayerState, void* AssetIdToCheck, bool BaseOnly)) {
	FOwnershipResponse* response = o_GetOwnershipFromPlayerControllerAndState(result, PlayerController, PlayerState, AssetIdToCheck, BaseOnly);
	response->owned = true;
	response->level = 0;
	return response;
}

DECL_HOOK(FOwnershipResponse*, CanUseLoadoutItem, (ATBLPlayerController* _this, FOwnershipResponse* result, const void* InLoadOutSelection, const void* InItem)) {
	auto response = o_CanUseLoadoutItem(_this, result, InLoadOutSelection, InItem); response->owned = true;
	response->level = 0;
	result->owned = true;
	return response;
}

DECL_HOOK(FOwnershipResponse*, CanUseCharacter, (ATBLPlayerController* _this, FOwnershipResponse* result, const void* CharacterSubclass)) {
	auto response = o_CanUseCharacter(_this, result, CharacterSubclass); 
	response->level = 0;
	response->owned = true;
	return response;
}

DECL_HOOK(void*, SendRequest, (GCGObj* this_ptr, FString* fullUrlInputPtr, FString* bodyContentPtr, FString* authKeyHeaderPtr, FString* authKeyValuePtr)) {
	if (fullUrlInputPtr->letter_count > 0 &&
		wcscmp(L"https://EBF8D.playfabapi.com/Client/Matchmake?sdk=Chiv2_Version", fullUrlInputPtr->str) == 0)
	{
		FString original = *fullUrlInputPtr; //save original string and buffer information
		*fullUrlInputPtr = FString(GetApiUrl(L"/api/playfab/Client/Matchmake").c_str()); //overwrite with new string
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

DECL_HOOK(FString, ConsoleCommand, (void* this_ptr, FString const& str, bool b)) {
#ifdef _DEBUG_
	static void* cached_this;
	if (this_ptr == NULL) {
		this_ptr = cached_this;
	}
	else {
		if (cached_this != this_ptr) {
			cached_this = this_ptr;
			//std::cout << "0x" << std::hex << this_ptr << std::endl;
		}
	}

	log("[RCON][DEBUG]: PlayerController Exec called with:");
	logWideString(str.str);

	const wchar_t* interceptPrefix = L"RCON_INTERCEPT";
	//if the command starts with the intercept prefix
	//TODO: clean up mutex stuff here. Way too sloppy to be final
	if (wcslen(str.str) >= 14 && memcmp(str.str, interceptPrefix, lstrlenW(interceptPrefix) * sizeof(wchar_t)) == 0) {

		log("[RCON][DEBUG]: Intercept command detected");
	}
#endif
	
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

// FRONTEND_MAP_FMT L"Frontend%ls?mods=%ls?nextmap=%ls?nextmods=%ls?defmods=%ls"
DECL_HOOK(bool, LoadFrontEndMap, (void* this_ptr, FString* param_1))
{
	static wchar_t szBuffer[512];

	static bool init = false;
	if (true) {
		auto pwdStr = CmdParseParam(L"ServerPassword", L"?Password=");

		log("Frontend Map params: ");
		wsprintfW(szBuffer, L"Frontend%ls%ls%ls", (CmdGetParam(L"-rcon") == -1) ? L"" : L"?rcon", pwdStr.c_str(), init ? L"" : L"?startup");
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
	// This is extremely loud in the console
	//if (input->str != NULL) {
	//	printf("FText_AsCultureInvariant: ");
	//	wprintf(input->str);
	//  printf("\n");
	//}
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
		void * res = o_FText_AsCultureInvariant(&txt, new FString2(L"Command detected"));
		if (res != NULL && CurGameMode != NULL)
		{
			log("[ChatCommands] Could print server text");
			o_BroadcastLocalizedChat(CurGameMode, (FText *)res, 3);
		}

		log("[ChatCommands] Executing command");
		logWideString(const_cast<wchar_t*>(command->c_str()));

		auto empty = FString2(command->c_str());

		o_ExecuteConsoleCommand(&empty);
	}
	else {
		//std::wcout << L"No valid match found." << std::endl;
	}
	o_ClientMessage(this_ptr, param_1, param_2, param_3);
}

void* UWORLD = nullptr;
DECL_HOOK(uint8_t, InternalGetNetMode, (void* world))
{
	UWORLD = world;
	return o_InternalGetNetMode(world);
}

bool playableListen = CmdGetParam(L"--playable-listen") != -1;
DECL_HOOK(bool, UGameplay__IsDedicatedServer, (long long param_1))
{
	if (UWORLD != nullptr && !playableListen) {
		return o_InternalGetNetMode(UWORLD) == 2;
	}
	else return o_UGameplay__IsDedicatedServer(param_1);
}


#ifdef PRINT_CLIENT_MSG
/*
void __thiscall
APlayerController::ClientMessage
		  (APlayerController *this,FString *param_1,FName param_2,float param_3)
*/
DECL_HOOK(void, ClientMessage, (void* this_ptr, FString* param_1, void* param_2, float param_3))
{
	std::wstring commandLine = GetCommandLineW();
	size_t flagLoc = commandLine.find(L"--next-map");
	bool egs = CmdGetParam(L"-epicapp=Peppermint") != -1;
	static uint64_t init = false;
	log("ClientMessage");

	wprintf(L"CLIENT_MESSAGE: %ls %.2f\n", param_1->str, param_3);

	std::wstring ws(param_1->str);
	std::string msg_str(ws.begin(), ws.end());
	o_ClientMessage(this_ptr, param_1, param_2, param_3);
}

#endif // PRINT_CLIENT_MSG

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
	inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

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
		FString2 commandString(command->c_str());
		o_ExecuteConsoleCommand(&commandString);
	}

	return;
}

unsigned long main_thread(void* lpParameter) {
	log(UNCHAINED_LOGO);
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
	HOOK_ATTACH(module_base, CanUseLoadoutItem);
	HOOK_ATTACH(module_base, CanUseCharacter);
	HOOK_ATTACH(module_base, UGameplay__IsDedicatedServer);
	HOOK_ATTACH(module_base, InternalGetNetMode);

	bool useBackendBanList = CmdGetParam(L"--use-backend-banlist") != -1;
	if (useBackendBanList) {
		HOOK_ATTACH(module_base, FString_AppendChars);
		HOOK_ATTACH(module_base, PreLogin);

	}

	bool IsHeadless = CmdGetParam(L"-nullrhi") != -1;
	if (IsHeadless) {
		HOOK_ATTACH(module_base, GetOwnershipFromPlayerControllerAndState);
	}

#ifdef PRINT_CLIENT_MSG
	HOOK_ATTACH(module_base, ClientMessage);
#endif 
	
	HOOK_ATTACH(module_base, ClientMessage);
	HOOK_ATTACH(module_base, ExecuteConsoleCommand);
	HOOK_ATTACH(module_base, GetTBLGameMode);
	HOOK_ATTACH(module_base, FText_AsCultureInvariant);
	HOOK_ATTACH(module_base, BroadcastLocalizedChat);
	
	// ServerPlugin
	auto cmd_permission{ module_base + curBuild.offsets[F_UTBLLocalPlayer_Exec] }; // Patch for command permission when executing commands (UTBLLocalPlayer::Exec)

	// From ServerPlugin
	// Patch for command permission when executing commands (UTBLLocalPlayer::Exec)
	Ptch_Repl(module_base + curBuild.offsets[F_UTBLLocalPlayer_Exec], 0xEB);
	
	/*printf("offset dedicated: 0x%08X", curBuild.offsets[F_UGameplay__IsDedicatedServer] + 0x22);
	Ptch_Repl(module_base + curBuild.offsets[F_UGameplay__IsDedicatedServer] + 0x22, 0x2);*/
	// Dedicated server hook in ApproveLogin
	//Nop(module_base + curBuild.offsets[F_ApproveLogin] + 0x46, 6);

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
