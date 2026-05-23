// Copyright © 2026 SculkCatalystMC. All rights reserved.
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of the MPL was not
// distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

#pragma once
#include "AuthenticationKeyManager.hpp"
#include "sculk/protocol/utility/Result.hpp"
#include <array>
#include <format>
#include <string>
#include <vector>

namespace sculk::protocol::inline abi_v975 {

class ClientProperties {
public:
    struct Header {
        std::string alg{};
        std::string x5u{};
    };

    struct AnimatedImage {
        int         mAnimationExpression{};
        float       mFrames{};
        std::string mImage{};
        int         mImageHeight{};
        int         mImageWidth{};
        int         mType{};
    };

    struct PersonaPiece {
        bool        mIsDefault{};
        std::string mPackId{};
        std::string mPieceId{};
        std::string mPieceType{};
        std::string mProductId{};
    };

    struct PieceTintColor {
        std::array<std::string, 4> mColors{};
        std::string                mPieceType{};
    };

    struct Payload {
        std::vector<AnimatedImage>  mAnimatedImageData{};
        std::string                 mArmSize{};
        std::string                 mCapeData{};
        std::string                 mCapeId{};
        int                         mCapeImageHeight{};
        int                         mCapeImageWidth{};
        bool                        mCapeOnClassicSkin{};
        uint64_t                    mClientRandomId{};
        bool                        mCompatibleWithClientSideChunkGen{};
        int                         mCurrentInputMode{};
        int                         mDefaultInputMode{};
        std::string                 mDeviceId{};
        std::string                 mDeviceModel{};
        int                         mDeviceOS{};
        bool                        mFilterProfanity{};
        std::string                 mGameVersion{};
        int                         mGraphicsMode{};
        int                         mGuiScale{};
        bool                        mIsEditorMode{};
        bool                        mIsPartyLeader{};
        std::string                 mLanguageCode{};
        int                         mMaxViewDistance{};
        int                         mMemoryTier{};
        bool                        mOverrideSkin{};
        std::string                 mPartyId{};
        std::vector<PersonaPiece>   mPersonaPieces{};
        bool                        mPersonaSkin{};
        std::vector<PieceTintColor> mPieceTintColors{};
        std::string                 mPlatformOfflineId{};
        std::string                 mPlatformOnlineId{};
        int                         mPlatformType{};
        std::string                 mPlayFabId{};
        bool                        mPremiumSkin{};
        std::string                 mSelfSignedId{};
        std::string                 mServerAddress{};
        std::string                 mSkinAnimationData{};
        std::string                 mSkinColor{};
        std::string                 mSkinData{};
        std::string                 mSkinGeometryData{};
        std::string                 mSkinGeometryDataEngineVersion{};
        std::string                 mSkinId{};
        int                         mSkinImageHeight{};
        int                         mSkinImageWidth{};
        std::string                 mSkinResourcePatch{};
        std::string                 mThirdPartyName{};
        bool                        mTrustedSkin{};
        int                         mUIProfile{};
    };

public:
    std::string mRawHeader{};
    Header      mHeader{};
    std::string mRawPayload{};
    Payload     mPayload{};
    std::string mSignature{};

public:
    [[nodiscard]] const Payload& getPayload() const { return mPayload; }

    [[nodiscard]] const std::vector<AnimatedImage>& getAnimatedImageData() const { return mPayload.mAnimatedImageData; }

    [[nodiscard]] std::string_view getArmSize() const { return mPayload.mArmSize; }

    [[nodiscard]] std::string_view getCapeData() const { return mPayload.mCapeData; }

    [[nodiscard]] std::string_view getCapeId() const { return mPayload.mCapeId; }

    [[nodiscard]] int getCapeImageHeight() const { return mPayload.mCapeImageHeight; }

    [[nodiscard]] int getCapeImageWidth() const { return mPayload.mCapeImageWidth; }

    [[nodiscard]] bool isCapeOnClassicSkin() const { return mPayload.mCapeOnClassicSkin; }

    [[nodiscard]] std::uint64_t getClientRandomId() const { return mPayload.mClientRandomId; }

    [[nodiscard]] bool isCompatibleWithClientSideChunkGen() const { return mPayload.mCompatibleWithClientSideChunkGen; }

    [[nodiscard]] int getCurrentInputMode() const { return mPayload.mCurrentInputMode; }

    [[nodiscard]] int getDefaultInputMode() const { return mPayload.mDefaultInputMode; }

    [[nodiscard]] std::string_view getDeviceId() const { return mPayload.mDeviceId; }

    [[nodiscard]] std::string_view getDeviceModel() const { return mPayload.mDeviceModel; }

    [[nodiscard]] int getDeviceOS() const { return mPayload.mDeviceOS; }

    [[nodiscard]] bool isFilterProfanity() const { return mPayload.mFilterProfanity; }

    [[nodiscard]] std::string_view getGameVersion() const { return mPayload.mGameVersion; }

    [[nodiscard]] int getGraphicsMode() const { return mPayload.mGraphicsMode; }

    [[nodiscard]] int getGuiScale() const { return mPayload.mGuiScale; }

    [[nodiscard]] bool isEditorMode() const { return mPayload.mIsEditorMode; }

    [[nodiscard]] bool isPartyLeader() const { return mPayload.mIsPartyLeader; }

    [[nodiscard]] std::string_view getLanguageCode() const { return mPayload.mLanguageCode; }

    [[nodiscard]] int getMaxViewDistance() const { return mPayload.mMaxViewDistance; }

    [[nodiscard]] int getMemoryTier() const { return mPayload.mMemoryTier; }

    [[nodiscard]] bool isOverrideSkin() const { return mPayload.mOverrideSkin; }

    [[nodiscard]] std::string_view getPartyId() const { return mPayload.mPartyId; }

    [[nodiscard]] const std::vector<PersonaPiece>& getPersonaPieces() const { return mPayload.mPersonaPieces; }

    [[nodiscard]] bool isPersonaSkin() const { return mPayload.mPersonaSkin; }

    [[nodiscard]] const std::vector<PieceTintColor>& getPieceTintColors() const { return mPayload.mPieceTintColors; }

    [[nodiscard]] std::string_view getPlatformOfflineId() const { return mPayload.mPlatformOfflineId; }

    [[nodiscard]] std::string_view getPlatformOnlineId() const { return mPayload.mPlatformOnlineId; }

    [[nodiscard]] int getPlatformType() const { return mPayload.mPlatformType; }

    [[nodiscard]] std::string_view getPlayFabId() const { return mPayload.mPlayFabId; }

    [[nodiscard]] bool isPremiumSkin() const { return mPayload.mPremiumSkin; }

    [[nodiscard]] std::string_view getSelfSignedId() const { return mPayload.mSelfSignedId; }

    [[nodiscard]] std::string_view getServerAddress() const { return mPayload.mServerAddress; }

    [[nodiscard]] std::string_view getSkinAnimationData() const { return mPayload.mSkinAnimationData; }

    [[nodiscard]] std::string_view getSkinColor() const { return mPayload.mSkinColor; }

    [[nodiscard]] std::string_view getSkinData() const { return mPayload.mSkinData; }

    [[nodiscard]] std::string_view getSkinGeometryData() const { return mPayload.mSkinGeometryData; }

    [[nodiscard]] std::string_view getSkinGeometryDataEngineVersion() const {
        return mPayload.mSkinGeometryDataEngineVersion;
    }

    [[nodiscard]] std::string_view getSkinId() const { return mPayload.mSkinId; }

    [[nodiscard]] int getSkinImageHeight() const { return mPayload.mSkinImageHeight; }

    [[nodiscard]] int getSkinImageWidth() const { return mPayload.mSkinImageWidth; }

    [[nodiscard]] std::string_view getSkinResourcePatch() const { return mPayload.mSkinResourcePatch; }

    [[nodiscard]] std::string_view getThirdPartyName() const { return mPayload.mThirdPartyName; }

    [[nodiscard]] bool isTrustedSkin() const { return mPayload.mTrustedSkin; }

    [[nodiscard]] int getUIProfile() const { return mPayload.mUIProfile; }

public:
    [[nodiscard]] Result<> verify(std::string_view publicKeyPem) const;

    [[nodiscard]] Result<> sign(const AuthenticationKeyManager& authenticationKeyManager);

    [[nodiscard]] std::string toString() const { return std::format("{}.{}.{}", mRawHeader, mRawPayload, mSignature); }

public:
    [[nodiscard]] static Result<ClientProperties> fromString(std::string_view rawClientProperties);
};

} // namespace sculk::protocol::inline abi_v975