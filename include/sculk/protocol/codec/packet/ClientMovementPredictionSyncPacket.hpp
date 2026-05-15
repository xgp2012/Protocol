// Copyright © 2026 SculkCatalystMC. All rights reserved.
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of the MPL was not
// distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

#pragma once
#include "sculk/protocol/codec/actor/ActorFlags.hpp"
#include "sculk/protocol/codec/packet/IPacket.hpp"
#include "sculk/protocol/codec/utility/math/Vec3.hpp"

namespace sculk::protocol::inline abi_v975 {

class ClientMovementPredictionSyncPacket : public IPacket {
public:
    struct MovementAttributesComponent {
        float mMovementSpeed{};
        float mUnderwaterMovementSpeed{};
        float mLavaMovementSpeed{};
        float mJumpStrength{};
        float mHealth{};
        float mHunger{};
        float mUnknown1{};
        float mUnknown2{};
        float mUnknown3{};

        void write(BinaryStream& stream) const;

        [[nodiscard]] Result<> read(ReadOnlyBinaryStream& stream);
    };

public:
    std::bitset<130>            mActorFlags{};
    Vec3                        mActorBoundingBox{};
    MovementAttributesComponent mMovementAttributes{};
    std::int64_t                mActorID{};
    bool                        mFlying{};

public:
    [[nodiscard]] MinecraftPacketIds getId() const noexcept override;

    [[nodiscard]] std::string_view getName() const noexcept override;

    void write(BinaryStream& stream) const override;

    [[nodiscard]] Result<> read(ReadOnlyBinaryStream& stream) override;
};

} // namespace sculk::protocol::inline abi_v975
