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
#include "tiny-json/tiny-json.h"
#include <winhttp.h>
#include <direct.h>
//always open output window
#define _DEBUG

#include "include/main.h"
#include "include/Chivalry2.h"
#include "include/UE4.h"


//black magic for the linker to get winsock2 to work
#pragma comment(lib, "Ws2_32.lib")

//always open output window
#define _DEBUG

//#define TARGET_API_ROOT L"localhost"

#include <cstdint>
#include <nmmintrin.h> // SSE4.2 intrinsics
#include <regex>

#define DEFAULT_SERVER_BROWSER_BACKEND L"https://servers.polehammer.net"
#define SERVER_BROWSER_BACKEND_CLI_ARG L"--server-browser-backend"

int logFString(FString str) {
	return logWideString(str.str);
}

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
//BuildInfo* curBuildInfo = nullptr;
BuildType curBuild;
bool jsonDone = false;
bool offsetsLoaded = false;
bool needsSerialization = true;

// This macro assumes that 'utf8bytes' is a null-terminated string.
#define UTF8_TO_TCHAR(utf8bytes) Utf8ToTChar(utf8bytes)

// Helper function that uses Windows API to convert UTF-8 to wchar_t array (TCHAR)
const wchar_t* Utf8ToTChar(const char* utf8bytes)
{
	// First, find out the required buffer size.
	int bufferSize = MultiByteToWideChar(CP_UTF8, 0, utf8bytes, -1, nullptr, 0);

	// Allocate buffer for WCHAR string.
	wchar_t* wcharString = new wchar_t[bufferSize];

	// Do the actual conversion.
	MultiByteToWideChar(CP_UTF8, 0, utf8bytes, -1, wcharString, bufferSize);

	return wcharString; // The caller is responsible for deleting this buffer after use.
}


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

// Returns position of a substring in command line args or -1
size_t CmdGetParam(const wchar_t* param)
{
	size_t res = std::wstring(GetCommandLineW()).find(param);
	bool found = (res != std::wstring::npos);

	//wprintf(L"CmdGetParam: %ls %ls %d\n", param, (found ? L":) found" : L":( not found"), found ? res : -1);
	return found ? res : -1;
}

// Returns parsed parameter (1 char spacing req), pre-/appends text if needed.
std::wstring CmdParseParam(const wchar_t* param, const wchar_t* addPrefix = L"", const wchar_t* addSuffix = L"")
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

std::wstring GetApiUrl(const wchar_t* path) {
	if (CmdGetParam(SERVER_BROWSER_BACKEND_CLI_ARG) != -1) {
		return CmdParseParam(SERVER_BROWSER_BACKEND_CLI_ARG, L"", path);
	}
	else {
		std::wstring baseUrl(DEFAULT_SERVER_BROWSER_BACKEND);
		return baseUrl + path;
	}
}

std::wstring HTTPGet(const std::wstring* url) {
	std::wstring response = L"";

	URL_COMPONENTSW lpUrlComponents = { 0 }; // Initialize the structure to zero.
	lpUrlComponents.dwStructSize = sizeof(URL_COMPONENTSW);
	lpUrlComponents.dwSchemeLength = (DWORD)-1;    // Let WinHttpCrackUrl allocate memory.
	lpUrlComponents.dwHostNameLength = (DWORD)-1;  // Let WinHttpCrackUrl allocate memory.
	lpUrlComponents.dwUrlPathLength = (DWORD)-1;   // Let WinHttpCrackUrl allocate memory.

	// Allocate buffers for the URL components
	wchar_t* schemeBuf = new wchar_t[url->length() + 1];
	wchar_t* hostNameBuf = new wchar_t[url->length() + 1];
	wchar_t* urlPathBuf = new wchar_t[url->length() + 1];

	// Assign buffers to the structure
	lpUrlComponents.lpszScheme = schemeBuf;
	lpUrlComponents.lpszHostName = hostNameBuf;
	lpUrlComponents.lpszUrlPath = urlPathBuf;

	bool success = WinHttpCrackUrl(url->c_str(), url->length(), 0, &lpUrlComponents);

	if(!success) {
		log("Failed to crack URL");
		DWORD error = GetLastError();

		switch (error)
		{
			case ERROR_WINHTTP_INTERNAL_ERROR:
				log("ERROR_WINHTTP_INTERNAL_ERROR");
				break;
			case ERROR_WINHTTP_INVALID_URL:
				log("ERROR_WINHTTP_INVALID_URL");
				break;
			case ERROR_WINHTTP_UNRECOGNIZED_SCHEME:
				log("ERROR_WINHTTP_UNRECOGNIZED_SCHEME");
				break;
			case ERROR_NOT_ENOUGH_MEMORY:
				log("ERROR_NOT_ENOUGH_MEMORY");
				break;
			default:
				break;
		}
		
		return response;
	}

	std::wstring host = std::wstring(lpUrlComponents.lpszHostName, lpUrlComponents.dwHostNameLength);
	std::wstring path = std::wstring(lpUrlComponents.lpszUrlPath, lpUrlComponents.dwUrlPathLength);
	std::wstring scheme = std::wstring(lpUrlComponents.lpszScheme, lpUrlComponents.dwSchemeLength);
	bool tls = scheme == L"https";
	int port = lpUrlComponents.nPort;

	BOOL bResults = FALSE;
	HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;
	DWORD dwSize = 0;
	DWORD dwDownloaded = 0;
	LPSTR pszOutBuffer;

	try {
		// Use WinHttpOpen to obtain a session handle.
		hSession = WinHttpOpen(L"Chivalry 2 Unchained/0.4",
			WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
			WINHTTP_NO_PROXY_NAME,
			WINHTTP_NO_PROXY_BYPASS, 0);

		// Specify an HTTP server.

		if (hSession) {
			hConnect = WinHttpConnect(hSession, host.c_str(), port, 0);
		}
		else {
			log("Failed to open WinHttp session");
		}

		// Create an HTTP request handle.
		if (hConnect)
			hRequest = WinHttpOpenRequest(hConnect, L"GET", path.c_str(),
				NULL, WINHTTP_NO_REFERER,
				WINHTTP_DEFAULT_ACCEPT_TYPES,
				tls ? WINHTTP_FLAG_SECURE : 0);
		else
			log("Failed to connect to WinHttp target");

		// Send a request.
		if (hRequest)
			bResults = WinHttpSendRequest(hRequest,
				WINHTTP_NO_ADDITIONAL_HEADERS, 0,
				WINHTTP_NO_REQUEST_DATA, 0,
				0, 0);
		else
			log("Failed to open WinHttp request");

		// End the request.
		if (bResults)
			bResults = WinHttpReceiveResponse(hRequest, NULL);
		else
			log("Failed to send WinHttp request");

		// Keep checking for data until there is nothing left.
		if (bResults) {
			do {
				// Check for available data.
				dwSize = 0;
				if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) {
					printf("Error %u in WinHttpQueryDataAvailable.\n",
						GetLastError());
					break;
				}

				// Allocate space for the buffer.
				pszOutBuffer = new char[dwSize + 1];
				if (!pszOutBuffer) {
					printf("Out of memory\n");
					dwSize = 0;
					break;
				}
				else {
					// Read the data.
					ZeroMemory(pszOutBuffer, dwSize + 1);

					if (!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer,
						dwSize, &dwDownloaded)) {
						printf("Error %u in WinHttpReadData.\n", GetLastError());
					}
					else {
						// Data has been read successfully.
						std::wstring chunk = UTF8_TO_TCHAR(pszOutBuffer);
						response.append(chunk);
					}

					// Free the memory allocated to the buffer.
					delete[] pszOutBuffer;
				}
			} while (dwSize > 0);
		}
		else
			log("Failed to receive WinHttp response");

		if (!hRequest || !hConnect || !hSession) {
			log("Failed to open WinHttp handles");
			std::wstring message =
				L"Host: " + host + L"\n" +
				L"Port: " + std::to_wstring(port) + L"\n" +
				L"Path: " + path + L"\n" +
				L"TLS: " + std::to_wstring(tls);
			logWideString(message.c_str());
		}
	}
	catch (...) {
		log("Exception in HTTPGet");
		delete[] schemeBuf;
		delete[] hostNameBuf;
		delete[] urlPathBuf;
		if (hRequest) WinHttpCloseHandle(hRequest);
		if (hConnect) WinHttpCloseHandle(hConnect);
		if (hSession) WinHttpCloseHandle(hSession);
		throw;
	}
	delete[] schemeBuf;
	delete[] hostNameBuf;
	delete[] urlPathBuf;
	// Close any open handles.
	if (hRequest) WinHttpCloseHandle(hRequest);
	if (hConnect) WinHttpCloseHandle(hConnect);
	if (hSession) WinHttpCloseHandle(hSession);

	return response;
}
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
DECL_HOOK(FString, ConsoleCommand, (void* this_ptr, FString const& str, bool b)) {
	static void* cached_this;
	if (this_ptr == NULL) {
		this_ptr = cached_this;
	}
	else {
		cached_this = this_ptr;
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

//#define FRONTEND_MAP_FMT L"Frontend%ls?mods=%ls?nextmap=%ls?nextmods=%ls?defmods=%ls"
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
		//if (false) {
		//	wcscpy_s(param_1->str, lstrlenW(param_1->str) + 1, command->c_str());
		//	o_ConsoleCommand(cached_this, *param_1, false);
		//}
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
		queueLock.lock();
		log("[RCON]: added command to queue: ");
		logWideString(const_cast<wchar_t*>(command->c_str()));
		commandQueue.emplace(std::move(command)); //put the command into the queue
		queueLock.unlock();
	}

	return;
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
