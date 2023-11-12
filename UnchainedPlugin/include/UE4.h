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

#pragma pack(push, 0x01)

struct USkeletalMeshComponent {
    uint8_t padding_0x00[0x800];
    bool bForceCreatePhysicsState : 1;
    bool bUpdateJointsFromAnimation : 1;
    bool bDisableClothSimulation : 1;
    bool bDisableRigidBodyAnimNode : 1;
    bool bAllowAnimCurveEvaluation : 1;
    bool bDisableAnimCurves : 1;
    bool UnknownData_ORQS : 2;
    bool UnknownData_N9EG : 1;
    bool bCollideWithEnvironment : 1;
    bool bCollideWithAttachedChildren : 1;
    bool bLocalSpaceSimulation : 1;
    bool bResetAfterTeleport : 1;
    bool UnknownData_CX1K : 1;
    bool bDeferKinematicBoneUpdate : 1;
    bool bNoSkeletonUpdate : 1;
    bool bPauseAnims : 1;
    bool bUseRefPoseOnInitAnim : 1;
    bool bEnablePerPolyCollision : 1;
    bool bForceRefpose : 1;
    bool bOnlyAllowAutonomousTickPose : 1;
    bool bIsAutonomousTickPose : 1;
    bool bOldForceRefPose : 1;
    bool bShowPrePhysBones : 1;
    bool bRequiredBonesUpToDate : 1;
    bool bAnimTreeInitialised : 1;
    bool bIncludeComponentLocationIntoBounds : 1;
    bool bEnableLineCheckWithBounds : 1;
    bool bUseBendingElements : 1;
    bool bUseTetrahedralConstraints : 1;
    bool bUseThinShellVolumeConstraints : 1;
    bool bUseSelfCollisions : 1;
    bool bUseContinuousCollisionDetection : 1;
    bool bPropagateCurvesToSlaves : 1;
    bool bSkipKinematicUpdateWhenInterpolating : 1;
    bool bSkipBoundsUpdateWhenInterpolating : 1;
    bool UnknownData_9W0T : 1;
    bool bNeedsQueuedAnimEventsDispatched : 1;
    uint8_t padding_0x805[0x1];
};

#pragma pack(pop)
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