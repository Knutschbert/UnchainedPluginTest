#pragma once
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

//FViewport* __thiscall FViewport::FViewport(FViewport* this, FViewportClient* param_1)
struct FViewport_C
{
	uint8_t ph[0x20];
	FString AppVersionString;
};

struct GCGObj {
	FString url_base;
};

struct GetMotdRequest {
	uint8_t ph[0xD8];
	FString token;
};

// Technically the same as GetMotdRequest for now. Just figure they should be decoupled.
struct GetCurrentGamesRequest {
	uint8_t ph[0xD8];
	FString token;
};

struct FOwnershipResponse {
	bool owned;
	int32_t crowns;
	int32_t gold;
	int32_t usdCents;
	uint8_t levelType;
	int32_t level;
};

enum EOnlineStat
{
	OS_Invalid = 0,
	OS_Default = 1,
	OS_Store = 2,
	OS_Unknown = 3,
	OS_Campaign = 4,
	OS_Playtime = 5,
	OS_GlobalXp = 6,
	OS_ExperienceFootman = 7,
	OS_ExperienceArcher = 8,
	OS_ExperienceKnight = 9,
	OS_ExperienceVanguard = 10,
	OS_ExperienceWeaponAxe = 11,
	OS_ExperienceWeaponBastardSword = 12,
	OS_ExperienceWeaponBattleAxe = 13,
	OS_ExperienceWeaponCudgel = 14,
	OS_ExperienceWeaponDagger = 15,
	OS_ExperienceWeaponDaneAxe = 16,
	OS_ExperienceWeaponGreatsword = 17,
	OS_ExperienceWeaponHalberd = 18,
	OS_ExperienceWeaponHeavyMace = 19,
	OS_ExperienceWeaponLance = 20,
	OS_ExperienceWeaponMace = 21,
	OS_ExperienceWeaponMaul = 22,
	OS_ExperienceWeaponMesser = 23,
	OS_ExperienceWeaponPoleAxe = 24,
	OS_ExperienceWeaponPoleHammer = 25,
	OS_ExperienceWeaponShortSword = 26,
	OS_ExperienceWeaponSpear = 27,
	OS_ExperienceWeaponSword = 28,
	OS_ExperienceWeaponWarHammer = 29,
	OS_ExperienceWeaponBow = 30,
	OS_ExperienceWeaponCrossbow = 31,
	OS_ExperienceWeaponThrowingAxe = 32,
	OS_ExperienceWeaponThrowingKnife = 33,
	OS_ExperienceWeaponHeavyShield = 34,
	OS_ExperienceWeaponLightShield = 35,
	OS_ExperienceWeaponMediumShield = 36,
	OS_ExperienceWeaponJavelin = 37,
	OS_ExperienceWeaponFalchion = 38,
	OS_ExperienceWeaponShovel = 39,
	OS_ExperienceWeaponSledgeHammer = 40,
	OS_ExperienceWeaponPickAxe = 41,
	OS_ExperienceWeaponTwoHandedHammer = 42,
	OS_ExperienceWeaponWarClub = 43,
	OS_ExperienceWeaponExecutionersAxe = 44,
	OS_ExperienceWeaponGlaive = 45,
	OS_ExperienceWeaponKnife = 46,
	OS_ExperienceWeaponWarAxe = 47,
	OS_ExperienceWeaponMorningStar = 48,
	OS_ExperienceWeaponHatchet = 49,
	OS_ExperienceWeaponOneHandedSpear = 50,
	OS_ExperienceWeaponThrowingMallet = 51,
	OS_ExperienceWeaponRapier = 52,
	OS_ExperienceWeaponHighlandSword = 53,
	OS_ExperienceWeaponWarBow = 54,
	OS_ExperienceWeaponHeavyCrossbow = 55,
	OS_ExperienceWeaponKatars = 56,
	OS_ExperienceWeaponArmouredFists = 57,
	OS_DailyPlaytime = 58,
	OS_PROGRESSION_MAX = 59,
	OS_Kills = 60,
	OS_Deaths = 61,
	OS_Suicides = 62,
	OS_WinsAgatha = 63,
	OS_LossesAgatha = 64,
	OS_WinsMason = 65,
	OS_LossesMason = 66,
	OS_MatchesCompleted = 67,
	OS_MatchesCompletedTeamObjective = 68,
	OS_MatchesCompletedTeamDeathmatch = 69,
	OS_MatchesCompletedFreeForAll = 70,
	OS_MatchesCompletedArena = 71,
	OS_MatchesCompletedLastTeamStanding = 72,
	OS_MatchesCompletedBrawl = 73,
	OS_ItemsConstructed = 74,
	OS_Revives = 75,
	OS_DISUSED_A = 76,
	OS_DISUSED_B = 77,
	OS_DISUSED_C = 78,
	OS_DamageInflicted = 79,
	OS_Blocks = 80,
	OS_FFAFirst = 81,
	OS_FFASecond = 82,
	OS_FFAThird = 83,
	OS_MultiKills = 84,
	OS_KillingSprees = 85,
	OS_VoteKickSeverity = 86,
	OS_VoteKickTime = 87,
	OS_WinsTenosia = 88,
	OS_LossesTenosia = 89,
	OS_FLAVOR_MAX = 90,
};

static const char* EOnlineStatStr[] = {
	"Invalid",
"Default",
"Store",
"Unknown",
"Campaign",
"Playtime",
"GlobalXp",
"ExperienceFootman",
"ExperienceArcher",
"ExperienceKnight",
"ExperienceVanguard",
"ExperienceWeaponAxe",
"ExperienceWeaponBastardSword",
"ExperienceWeaponBattleAxe",
"ExperienceWeaponCudgel",
"ExperienceWeaponDagger",
"ExperienceWeaponDaneAxe",
"ExperienceWeaponGreatsword",
"ExperienceWeaponHalberd",
"ExperienceWeaponHeavyMace",
"ExperienceWeaponLance",
"ExperienceWeaponMace",
"ExperienceWeaponMaul",
"ExperienceWeaponMesser",
"ExperienceWeaponPoleAxe",
"ExperienceWeaponPoleHammer",
"ExperienceWeaponShortSword",
"ExperienceWeaponSpear",
"ExperienceWeaponSword",
"ExperienceWeaponWarHammer",
"ExperienceWeaponBow",
"ExperienceWeaponCrossbow",
"ExperienceWeaponThrowingAxe",
"ExperienceWeaponThrowingKnife",
"ExperienceWeaponHeavyShield",
"ExperienceWeaponLightShield",
"ExperienceWeaponMediumShield",
"ExperienceWeaponJavelin",
"ExperienceWeaponFalchion",
"ExperienceWeaponShovel",
"ExperienceWeaponSledgeHammer",
"ExperienceWeaponPickAxe",
"ExperienceWeaponTwoHandedHammer",
"ExperienceWeaponWarClub",
"ExperienceWeaponExecutionersAxe",
"ExperienceWeaponGlaive",
"ExperienceWeaponKnife",
"ExperienceWeaponWarAxe",
"ExperienceWeaponMorningStar",
"ExperienceWeaponHatchet",
"ExperienceWeaponOneHandedSpear",
"ExperienceWeaponThrowingMallet",
"ExperienceWeaponRapier",
"ExperienceWeaponHighlandSword",
"ExperienceWeaponWarBow",
"ExperienceWeaponHeavyCrossbow",
"ExperienceWeaponKatars",
"ExperienceWeaponArmouredFists",
"DailyPlaytime",
"PROGRESSION_MAX",
"Kills",
"Deaths",
"Suicides",
"WinsAgatha",
"LossesAgatha",
"WinsMason",
"LossesMason",
"MatchesCompleted",
"MatchesCompletedTeamObjective",
"MatchesCompletedTeamDeathmatch",
"MatchesCompletedFreeForAll",
"MatchesCompletedArena",
"MatchesCompletedLastTeamStanding",
"MatchesCompletedBrawl",
"ItemsConstructed",
"Revives",
"DISUSED_A",
"DISUSED_B",
"DISUSED_C",
"DamageInflicted",
"Blocks",
"FFAFirst",
"FFASecond",
"FFAThird",
"MultiKills",
"KillingSprees",
"VoteKickSeverity",
"VoteKickTime",
"WinsTenosia",
"LossesTenosia",
"FLAVOR_MAX",
};

struct ATBLPlayerController { };

// Helper functions

void log(const char* str) {
#ifndef _DEBUG
	return;
#endif
	std::cout << str << std::endl;

}


int logWideString(wchar_t* str) {
#ifndef _DEBUG
	return 0;
#endif
	int i = 0;
	while (*(wchar_t*)str != 0) {
		std::wcout << *(wchar_t*)str;
		str++;
		i++;
	}
	std::wcout << std::endl;
	return i;
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
